/* SPDX-License-Identifier: MIT. Opt-in QEMU tests inside the genuine XNU kernel.
 * No replacement kernel services, security bypasses or physical-device I/O.
 */
#include <stdint.h>
#include <string.h>
#include <kern/debug.h>
#include <kern/startup.h>
#include <kern/thread.h>
#include <kern/ipc_mig.h>
#include <machine/machine_routines.h>
#include <mach/vm_statistics.h>
#include <vm/vm_kern.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_kmsg.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <libkern/section_keywords.h>
#include "ums512_img4.h"

struct ums512_runtime_proof {
    uint64_t magic, complete, phase, vm_allocations, verified_bytes;
    uint64_t ports, message_roundtrips, signature_vectors;
};
SECURITY_READ_ONLY_LATE(volatile struct ums512_runtime_proof) ums512_runtime_proof;
_Static_assert(sizeof(struct ums512_runtime_proof) == 64, "debugger proof ABI");

static void vm_tests(void)
{
    static const unsigned pages[] = {1,3,5,17};
    for (unsigned repeat=0; repeat<2; repeat++) {
        for (unsigned c=0; c<4; c++) {
            vm_offset_t addr=0;
            vm_size_t size=PAGE_SIZE*pages[c];
            if (kmem_alloc(kernel_map,&addr,size,KMA_KOBJECT|KMA_DATA|KMA_ZERO,VM_KERN_MEMORY_OSFMK) != KERN_SUCCESS) {
                panic("UMS512 runtime test: wired allocation failed");
            }
            volatile uint64_t *data=(volatile uint64_t *)addr;
            for (vm_size_t i=0; i<size/sizeof(*data); i++) {
                if (data[i] != 0) { panic("UMS512 runtime test: zero-fill mismatch"); }
            }
            for (unsigned pass=0; pass<2; pass++) {
                uint64_t pattern=UINT64_C(0x726d7833786e7531) ^ repeat ^ ((uint64_t)pass<<48);
                for (vm_size_t i=0; i<size/sizeof(*data); i++) { data[i]=pattern ^ i; }
                for (vm_size_t i=0; i<size/sizeof(*data); i++) {
                    if (data[i] != (pattern ^ i)) { panic("UMS512 runtime test: wired data mismatch"); }
                }
            }
            kmem_free(kernel_map,addr,size);
            ums512_runtime_proof.vm_allocations++;
            ums512_runtime_proof.verified_bytes += size;
        }
    }
}

static void ipc_tests(void)
{
    thread_t self=current_thread();
    for (unsigned p=0; p<4; p++) {
        /* A private kernel reply-space queue, never a kobject dispatch port. */
        ipc_port_t port=ipc_port_alloc_special(ipc_space_reply,IPC_PORT_INIT_MESSAGE_QUEUE);
        if (port == IP_NULL) { panic("UMS512 runtime test: port allocation failed"); }
        for (unsigned n=0; n<2; n++) {
            struct { mach_msg_header_t h; uint64_t data[3]; } msg;
            memset(&msg,0,sizeof(msg));
            msg.h.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND,0);
            msg.h.msgh_size=(mach_msg_size_t)sizeof(msg);
            msg.h.msgh_id=(mach_msg_id_t)(0x524d5800+p*2+n);
            msg.h.msgh_remote_port=ipc_port_make_send_mqueue(port);
            if (msg.h.msgh_remote_port != port) { panic("UMS512 runtime test: make-send failed"); }
            msg.data[0]=UINT64_C(0x524d58584e555431) ^ ((uint64_t)p<<32) ^ n;
            msg.data[1]=~msg.data[0]; msg.data[2]=msg.data[0]+0x1234;
            if (mach_msg_send_from_kernel_proper(&msg.h,(mach_msg_size_t)sizeof(msg)) != MACH_MSG_SUCCESS) {
                panic("UMS512 runtime test: kernel message send failed");
            }
            /* Own the sole receive right. No other thread can consume this queue. */
            mach_msg_return_t saved_state=self->ith_state;
            ipc_kmsg_t saved_kmsg=self->ith_kmsg;
            mach_port_seqno_t saved_seqno=self->ith_seqno;
            ipc_mqueue_receive(&port->ip_waitq,MACH_RCV_MSG|MACH_RCV_TIMEOUT,
                4096,0,0,THREAD_UNINT,false);
            mach_msg_return_t state=self->ith_state;
            ipc_kmsg_t received=self->ith_kmsg;
            self->ith_state=saved_state; self->ith_kmsg=saved_kmsg; self->ith_seqno=saved_seqno;
            if (state != MACH_MSG_SUCCESS || received == IKM_NULL) {
                panic("UMS512 runtime test: kernel message receive failed: %x",state);
            }
            if (ikm_header(received)->msgh_id != msg.h.msgh_id ||
                memcmp(ikm_udata(received,0,false),msg.data,sizeof(msg.data))) {
                panic("UMS512 runtime test: kernel message payload mismatch");
            }
            /* Normal destruction retains signature validation and releases rights. */
            ipc_kmsg_destroy(received,IPC_KMSG_DESTROY_ALL);
            ums512_runtime_proof.message_roundtrips++;
        }
        ipc_port_dealloc_special(port,ipc_space_reply);
        ums512_runtime_proof.ports++;
    }
}

void ums512_runtime_selftest(void);
void ums512_runtime_selftest(void)
{
    int enabled=0;
    DTEntry root;
    const void *model=NULL;
    unsigned size=0;
    static const char expected[]="qemu,virt";
    if (!PE_parse_boot_argn("ums512-selftest",&enabled,sizeof(enabled)) || !enabled) { return; }
    if (SecureDTLookupEntry(NULL,"/",&root) != kSuccess ||
        SecureDTGetProperty(root,"model",&model,&size) != kSuccess ||
        size != sizeof(expected) || memcmp(model,expected,sizeof(expected))) { return; }
    if (!ml_get_interrupts_enabled()) { panic("UMS512 runtime test: wrong initialization phase"); }
    ums512_runtime_proof.magic=UINT64_C(0x524d58584e555431);
    ums512_runtime_proof.phase=1;
    vm_tests();
    ums512_runtime_proof.phase=2;
    ipc_tests();
    ums512_runtime_proof.phase=3;
    ums512_runtime_proof.signature_vectors=ums512_img4_selftest();
    if (ums512_runtime_proof.signature_vectors!=30) { panic("UMS512 Image4 test vector count mismatch"); }
    ums512_runtime_proof.complete=1;
}
