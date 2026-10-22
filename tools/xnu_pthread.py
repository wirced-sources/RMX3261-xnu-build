"""Install the pinned genuine libpthread kernel implementation, monolithically.

No kext-loader/signing override is involved. Source notices are retained. Only
four module-private names are isolated to avoid collisions with XNU core.
"""
from pathlib import Path
import shutil
import shlex

def install(source, xnu):
    source,xnu=Path(source),Path(xnu)
    target=xnu/'bsd/ums512_pthread'
    target.mkdir()
    vendor=target/'vendor'
    for directory in ('kern','private','include'):
        shutil.copytree(source/directory,vendor/directory)
    def correct(relative, old, new, count=1):
        path=vendor/relative; text=path.read_text(encoding='utf-8')
        if text.count(old)!=count:raise ValueError('pinned pthread source changed: '+relative)
        path.write_text(text.replace(old,new),encoding='utf-8',newline='\n')
    correct('kern/kern_trace.h','vm_kernel_unslide_or_perm_external(ptr,','vm_kernel_unslide_or_perm_external((vm_offset_t)ptr,')
    correct('kern/kern_support.c','extern void panic(const char *string, ...) __printflike(1,2) __dead2;',
            '#include <kern/debug.h> /* Real noreturn prototype and decorated panic macro. */')
    correct('kern/kern_support.c','*kevent_list_out = NULL;','*kevent_list_out = 0;')
    correct('kern/kern_support.c','user_addr_t kevent_list = NULL;','user_addr_t kevent_list = 0;',count=2)
    correct('kern/kern_support.c','workq_kevent(p, &th_addrs, NULL, 0,','workq_kevent(p, &th_addrs, 0, 0,')
    correct('kern/kern_support.c','\t\t\t\t\t\tqos.qos_tier, 0, 0);',
            '\t\t\t\t\t\t(thread_qos_t)qos.qos_tier, 0, 0);')
    correct('kern/kern_support.c','if (kr == KERN_SUCCESS) {\n\t\t\t\tdata.main_qos',
            'if (kr == KERN_SUCCESS) {\n\t\t\t\tif ((unsigned)qos.qos_tier >= THREAD_QOS_LAST) { return EINVAL; }\n\t\t\t\tdata.main_qos')
    for name,count in (('psynch_wait_update_owner',4),('psynch_wait_complete',1),('psynch_wait_wakeup',2)):
        correct('kern/kern_synch.c',name+'(kwq,',name+'((uintptr_t)kwq,',count=count)
    correct('kern/kern_synch.c','kwe->kwe_state = state;',
            'if (state>UINT16_MAX) { panic("pthread: prepost state exceeds wait element ABI"); }\n\tkwe->kwe_state = (uint16_t)state;')
    for name in ('LICENSE','APPLE_LICENSE'):
        if (source/name).is_file():shutil.copyfile(source/name,vendor/name)
    prefix='''/* Genuine pinned libpthread, original kext header context. */
#undef BSD_KERNEL_PRIVATE
#undef MACH_KERNEL
#define XNU_KERNEL_PRIVATE 1
#define MACH_KERNEL_PRIVATE 1
#define ABSOLUTETIME_SCALAR_TYPE 1
#define NEEDS_SCHED_CALL_T 1
#define __PTHREAD_EXPOSE_INTERNALS__ 1
#define pthread_kern ums512_pthread_callbacks
#define current_uthread ums512_pthread_current_uthread
#define pthread_start ums512_pthread_start
#define pthread_stop ums512_pthread_stop
#include <kern/kern_types.h>
#include <kern/kcdata.h>
#include <sys/kernel_types.h>
#include <libkern/zlib.h>
'''
    for unit in ('init','support','synch'):
        (target/f'pthread_vendor_{unit}.c').write_text(prefix+f'#include "vendor/kern/kern_{unit}.c"\n'+
            '_Static_assert(sizeof(struct ksyn_waitq_element)==56,"libpthread ARM64 wait element ABI");\n'+
            '_Static_assert(_Alignof(struct ksyn_waitq_element)==8,"libpthread wait element alignment");\n',encoding='utf-8',newline='\n')
    shutil.copyfile(Path(__file__).resolve().parents[1]/'xnu/platform/ums512/ums512_pthread.c',target/'ums512_pthread.c')
    with (xnu/'bsd/conf/files').open('a',newline='\n') as stream:
        for unit in ('pthread_vendor_init','pthread_vendor_support','pthread_vendor_synch','ums512_pthread'):
            stream.write(f'\nbsd/ums512_pthread/{unit}.c\toptional ums512\n')

def flags(xnu, sdk, exported):
    """Use upstream per-object flags; do not shadow headers for other XNU units."""
    vendor=Path(xnu)/'bsd/ums512_pthread/vendor'
    # CFLAGS_ADD precedes native INCFLAGS. Raw OSFMK export roots contain a
    # standalone string.h expecting libsa/types.h. Use a genuine SDK string
    # prefix with the original private native exports, not mixed frameworks.
    # Only these three units get this context; no type facade is generated.
    # Keep the normal native export roots for private types. A genuine SDK
    # string prefix prevents the legacy standalone OSFMK string.h from being
    # selected. Include real kernel zlib first in the source prefix as well.
    paths=[Path(xnu)/'libkern']
    paths += [vendor/p for p in ('.','private','include')]
    prefix='-include '+shlex.quote(str(Path(sdk)/'usr/include/string.h'))+' '
    return [f'pthread_vendor_{unit}.o_CFLAGS_ADD='+prefix+' '.join('-I'+shlex.quote(str(p)) for p in paths)
            for unit in ('init','support','synch')]
