/* SPDX-License-Identifier: MIT. Bounded opt-in real BSD socket operations.
 * AF_LOCAL only: no guest networking, VFS paths or physical device access.
 */
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/kpi_socket.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <kern/debug.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>

struct ums512_bsd_socket_proof {
    uint64_t magic,complete,phase,pairs,messages,bytes,empty_rejections,eof_checks;
};
/* Mutable control counters: this test runs after security lockdown. */
volatile struct ums512_bsd_socket_proof ums512_bsd_socket_proof;
_Static_assert(sizeof(struct ums512_bsd_socket_proof)==64,"BSD socket proof ABI");

static __attribute__((noreturn)) void socket_failure(int error)
{
    panic("QEMU BSD socket test phase %llu error %d",ums512_bsd_socket_proof.phase,error);
}
static void empty_receive(socket_t so)
{
    unsigned char data[16];
    struct iovec io={.iov_base=data,.iov_len=sizeof(data)};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1};
    size_t got=SIZE_MAX;
    int error=sock_receive(so,&msg,MSG_DONTWAIT,&got);
    if (error!=EWOULDBLOCK || got!=0) socket_failure(error ? error : EIO);
    ums512_bsd_socket_proof.empty_rejections++;
}
static void transfer(socket_t from, socket_t to, size_t n, unsigned pattern)
{
    unsigned char data[320],received[320];
    struct iovec io={.iov_base=data,.iov_len=n};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1};
    size_t sent=0,got=0;
    for (size_t i=0;i<n;i++) data[i]=(unsigned char)(i*17+pattern);
    memset(received,0,sizeof(received));
    int error=sock_send(from,&msg,MSG_DONTWAIT|MSG_NOSIGNAL,&sent);
    if (error || sent!=n) socket_failure(error ? error : EIO);
    io.iov_base=received;
    error=sock_receive(to,&msg,MSG_DONTWAIT,&got);
    if (error || got!=n || (msg.msg_flags&MSG_TRUNC) || memcmp(data,received,n)) socket_failure(error ? error : EIO);
    ums512_bsd_socket_proof.messages++;
    ums512_bsd_socket_proof.bytes+=n;
}
void ums512_bsd_socket_selftest(void);
void ums512_bsd_socket_selftest(void)
{
    int enabled=0;
    DTEntry root;
    const void *model=NULL;
    unsigned length=0;
    static const char expected[]="qemu,virt";
    static const size_t sizes[]={1,37,257};
    if (!PE_parse_boot_argn("ums512-selftest",&enabled,sizeof(enabled)) || !enabled) return;
    if (SecureDTLookupEntry(NULL,"/",&root)!=kSuccess ||
        SecureDTGetProperty(root,"model",&model,&length)!=kSuccess ||
        length!=sizeof(expected) || memcmp(model,expected,sizeof(expected))) return;
    if (!ml_get_interrupts_enabled() || ums512_bsd_socket_proof.magic) socket_failure(EINVAL);
    ums512_bsd_socket_proof.magic=UINT64_C(0x524d584253445331);
    for (unsigned type=0;type<2;type++) {
        socket_t a=NULL,b=NULL;
        int kind=type ? SOCK_DGRAM : SOCK_STREAM;
        int error;
        ums512_bsd_socket_proof.phase=1;
        if ((error=sock_socket(AF_LOCAL,kind,0,NULL,NULL,&a)) ||
            (error=sock_socket(AF_LOCAL,kind,0,NULL,NULL,&b))) socket_failure(error);
        ums512_bsd_socket_proof.phase=2;
        if ((error=soconnect2(a,b)) || (type && (error=soconnect2(b,a)))) socket_failure(error);
        ums512_bsd_socket_proof.pairs++;
        ums512_bsd_socket_proof.phase=3;
        empty_receive(a);empty_receive(b);
        ums512_bsd_socket_proof.phase=4;
        for (unsigned i=0;i<3;i++) {
            transfer(a,b,sizes[i],type*16+i);
            transfer(b,a,sizes[i],type*16+i+8);
        }
        ums512_bsd_socket_proof.phase=5;
        sock_close(a);a=NULL;
        if (!type) {
            unsigned char data;
            struct iovec io={.iov_base=&data,.iov_len=1};
            struct msghdr msg={.msg_iov=&io,.msg_iovlen=1};
            size_t got=SIZE_MAX;
            error=sock_receive(b,&msg,MSG_DONTWAIT,&got);
            if (error || got) socket_failure(error ? error : EIO);
            ums512_bsd_socket_proof.eof_checks++;
        }
        sock_close(b);b=NULL;
    }
    ums512_bsd_socket_proof.phase=6;
    ums512_bsd_socket_proof.complete=1;
}
