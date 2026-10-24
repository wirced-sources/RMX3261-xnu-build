/* SPDX-License-Identifier: MIT
 * Actual mounted-HFS vnode operations after the unchanged BSD root-auth gate.
 * No executable, signature acceptance, VFS replacement or writable root.
 */
#include <stdint.h>
#include <string.h>
#include <kern/debug.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/fsctl.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/vfs_context.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>
#include <sys/uio.h>
#include <pexpert/pexpert.h>
#include "ums512_lab_codesign.h"

struct ums512_rootfs_proof {
    uint64_t magic,complete,reads,bytes;
    uint64_t eof_checks,write_denials,missing_denials,nonroot_auth_denials;
};
volatile struct ums512_rootfs_proof ums512_rootfs_proof;
_Static_assert(sizeof(struct ums512_rootfs_proof)==64,"public rootfs proof ABI");
void ums512_qemu_rootfs_selftest(void);

void ums512_qemu_rootfs_selftest(void)
{
    int requested=0;
    if (!PE_parse_boot_argn("ums512-selftest",&requested,sizeof(requested)) || requested!=1) { return; }
    static const char expected[]="Owned QEMU laboratory data; no Apple userland.\n";
    vfs_context_t context=vfs_context_kernel();
    vnode_t root=vfs_rootvnode(),file=NULLVP;
    if (!root || !vnode_isvroot(root) || !vfs_isrdonly(vnode_mount(root)) ||
        strcmp(vfs_statfs(vnode_mount(root))->f_fstypename,"hfs")) {
        panic("QEMU rootfs: actual readonly HFS root missing");
    }
    ums512_rootfs_proof.magic=0x524d585246533031ULL;
    int flags=VNODE_LOOKUP_NOFOLLOW|VNODE_LOOKUP_NOCROSSMOUNT;
    if (vnode_open("/root-proof.txt",FREAD,0,flags,&file,context) || !file ||
        vnode_vtype(file)!=VREG || vnode_mount(file)!=vnode_mount(root)) {
        panic("QEMU rootfs: authenticated root file could not be opened");
    }
    char buffer[sizeof(expected)]={0};
    int residual=0;
    if (vn_rdwr(UIO_READ,file,buffer,sizeof(expected)-1,0,UIO_SYSSPACE,0,
                vfs_context_ucred(context),&residual,vfs_context_proc(context)) || residual ||
        memcmp(buffer,expected,sizeof(expected)-1)) {
        panic("QEMU rootfs: real HFS vnode read mismatch");
    }
    ums512_rootfs_proof.reads++;
    ums512_rootfs_proof.bytes=sizeof(expected)-1;
    if (vn_rdwr(UIO_READ,file,buffer,4,sizeof(expected)-1,UIO_SYSSPACE,0,
                vfs_context_ucred(context),&residual,vfs_context_proc(context)) || residual!=4) {
        panic("QEMU rootfs: real HFS EOF mismatch");
    }
    ums512_rootfs_proof.eof_checks++;
    if (VNOP_IOCTL(file,FSIOC_KERNEL_ROOTAUTH,NULL,0,context)!=EAUTH) {
        panic("QEMU rootfs: nonroot vnode incorrectly authorized");
    }
    ums512_rootfs_proof.nonroot_auth_denials++;
    if (vnode_close(file,FREAD,context)) { panic("QEMU rootfs: close failed"); }
    file=NULLVP;
    if (vnode_open("/root-proof.txt",FWRITE,0,flags,&file,context)!=EROFS) {
        panic("QEMU rootfs: readonly write open was not rejected");
    }
    ums512_rootfs_proof.write_denials++;
    file=NULLVP;
    if (vnode_lookup("/rmx-deliberately-absent",flags,&file,context)!=ENOENT) {
        panic("QEMU rootfs: nonexistent file lookup mismatch");
    }
    ums512_rootfs_proof.missing_denials++;
    ums512_lab_vnode_negative_tests();
    ums512_rootfs_proof.complete=1;
}
