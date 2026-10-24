/* SPDX-License-Identifier: MIT
 * Genuine immutable vnode bytes and CMS/CD/page checks, native cs_blob binding.
 * All mutable/unknown filesystems remain denied to avoid check/use races.
 */
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/vfs_context.h>
#include <sys/uio.h>
#include <sys/ubc.h>
#include <sys/ubc_internal.h>
#include <sys/fcntl.h>
#include <kern/clock.h>
#include <kern/kalloc.h>
#include <kern/debug.h>
#include <os/atomic_private.h>
#include "ums512_lab_codesign.h"

volatile struct ums512_lab_exec_proof ums512_lab_exec_proof;
int ums512_lab_authorize_vnode(struct vnode *vp,struct cs_blob *blob)
{
    int error=EAUTH;
    if(!vp || !vnode_isreg(vp) || !vfs_isrdonly(vnode_mount(vp)) ||
       strcmp(vfs_statfs(vnode_mount(vp))->f_fstypename,"hfs")) return EAUTH;
    vfs_context_t context=vfs_context_current();struct vnode_attr va;
    VATTR_INIT(&va);VATTR_WANTED(&va,va_data_size);
    if(vnode_getattr(vp,&va,context) || va.va_data_size<32 || va.va_data_size>256*1024) return EAUTH;
    size_t length=(size_t)va.va_data_size;
    uint8_t *bytes=kalloc_data(length,Z_WAITOK);if(!bytes) return ENOMEM;
    int residual=0;uint8_t digest[32];
    clock_sec_t sec;clock_usec_t usec;clock_get_calendar_microtime(&sec,&usec);
    if(!vn_rdwr(UIO_READ,vp,(char *)bytes,(int)length,0,UIO_SYSSPACE,0,
                vfs_context_ucred(context),&residual,vfs_context_proc(context)) && !residual &&
       ums512_lab_verify_file(bytes,length,(uint64_t)sec,digest)) {
        error=0;
        if(blob) {
            if(!blob->csb_cd || blob->csb_base_offset || blob->csb_platform_binary || blob->csb_platform_path ||
               blob->csb_entitlements || blob->csb_entitlements_blob || blob->csb_der_entitlements_blob ||
               memcmp(blob->csb_cdhash,digest,20)) error=EAUTH;
            const uint8_t *cd=(const uint8_t *)blob->csb_cd;
            uintptr_t begin=(uintptr_t)blob->csb_mem_kaddr,ptr=(uintptr_t)cd;
            if(!error && (ptr<begin || ptr-begin>blob->csb_mem_size ||
                blob->csb_mem_size-(ptr-begin)<8)) error=EAUTH;
            if(!error) {
                uint32_t n=((uint32_t)cd[4]<<24)|((uint32_t)cd[5]<<16)|((uint32_t)cd[6]<<8)|cd[7];
                if(n>blob->csb_mem_size-(ptr-begin)) error=EAUTH;
                else {
                    size_t at=32;uint32_t cmds;memcpy(&cmds,bytes+16,4);
                    const uint8_t *expected=NULL;
                    for(uint32_t i=0;i<cmds;i++) {
                        uint32_t cmd,len;memcpy(&cmd,bytes+at,4);memcpy(&len,bytes+at+4,4);
                        if(cmd==0x1d) { uint32_t off;memcpy(&off,bytes+at+8,4);expected=bytes+off+28;break; }
                        at+=len;
                    }
                    uint32_t expected_n=expected?((uint32_t)expected[4]<<24)|((uint32_t)expected[5]<<16)|
                        ((uint32_t)expected[6]<<8)|expected[7]:0;
                    if(!expected || n!=expected_n || memcmp(cd,expected,n)) error=EAUTH;
                }
            }
        }
        if(!error) os_atomic_inc(&ums512_lab_exec_proof.files_verified,relaxed);
    }
    kfree_data(bytes,length);
    if(error) os_atomic_inc(&ums512_lab_exec_proof.denials,relaxed);
    return error;
}
void ums512_lab_vnode_negative_tests(void)
{
    static const char *const paths[]={"/sbin/unsigned-init","/sbin/altered-init","/sbin/bad-cms-init"};
    vfs_context_t context=vfs_context_kernel();
    for(unsigned i=0;i<3;i++) {
        vnode_t vp=NULLVP;
        if(vnode_open(paths[i],FREAD,0,VNODE_LOOKUP_NOFOLLOW|VNODE_LOOKUP_NOCROSSMOUNT,&vp,context) ||
            !vp || ums512_lab_authorize_vnode(vp,NULL)!=EAUTH) panic("QEMU lab untrusted vnode accepted");
        if(vnode_close(vp,FREAD,context)) panic("QEMU lab negative vnode close failed");
        os_atomic_inc(&ums512_lab_exec_proof.vnode_negative_tests,relaxed);
    }
}
