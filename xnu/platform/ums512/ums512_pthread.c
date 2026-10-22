/* SPDX-License-Identifier: MIT. Genuine monolithic libpthread registration. */
#include <stdint.h>
#include <string.h>
#include <mach/kmod.h>
#include <kern/debug.h>
#include <sys/pthread_shims.h>
#include <sys/pthread_internal.h>
#include <pexpert/device_tree.h>

extern const struct pthread_functions_s pthread_internal_functions;
extern pthread_callbacks_t ums512_pthread_callbacks;
extern kern_return_t ums512_pthread_start(kmod_info_t *,void *);
void ums512_pthread_register(void);
volatile uint64_t ums512_pthread_registered;
_Static_assert(sizeof(struct ksyn_waitq_element)==56,"native wait storage ABI");
_Static_assert(_Alignof(struct ksyn_waitq_element)==8,"native wait storage alignment");
_Static_assert(__builtin_offsetof(struct ksyn_waitq_element,kwe_uth)==48,"native wait element field ABI");

void ums512_pthread_register(void)
{
    DTEntry root;const void *model=NULL;unsigned length=0;
    static const char expected[]="qemu,virt";
    if (SecureDTLookupEntry(NULL,"/",&root)!=kSuccess ||
        SecureDTGetProperty(root,"model",&model,&length)!=kSuccess ||
        length!=sizeof(expected) || memcmp(model,expected,sizeof(expected))) {
        panic("QEMU pthread: unsupported platform");
    }
    if (ums512_pthread_registered || pthread_functions) { panic("QEMU pthread: duplicate registration"); }
    if (ums512_pthread_start(NULL,NULL)!=KERN_SUCCESS ||
        pthread_functions!=&pthread_internal_functions || !ums512_pthread_callbacks ||
        ums512_pthread_callbacks!=pthread_kern || !pthread_functions->pthread_init ||
        !pthread_functions->psynch_mutexwait || !pthread_functions->psynch_mutexdrop ||
        !pthread_functions->workq_setup_thread || !pthread_functions->workq_handle_stack_events ||
        pthread_functions->version>PTHREAD_FUNCTIONS_TABLE_VERSION) {
        panic("QEMU pthread: genuine module registration failed");
    }
    ums512_pthread_registered=1;
}
