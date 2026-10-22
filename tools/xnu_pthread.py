"""Install the pinned genuine libpthread kernel implementation, monolithically.

No kext-loader/signing override is involved. Source notices are retained. Only
four module-private names are isolated to avoid collisions with XNU core.
"""
from pathlib import Path
import shutil

def install(source, xnu):
    source,xnu=Path(source),Path(xnu)
    target=xnu/'bsd/ums512_pthread'
    target.mkdir()
    vendor=target/'vendor'
    for directory in ('kern','private','include'):
        shutil.copytree(source/directory,vendor/directory)
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
    # standalone string.h expecting libsa/types.h; a kext must use real SDK
    # and freshly installed Kernel.framework headers instead. Only these three
    # units get this order; no compatibility/type facade is generated.
    framework=Path('System/Library/Frameworks/Kernel.framework')
    paths=[Path(exported)/framework/p for p in ('PrivateHeaders','Headers')]
    paths += [Path(sdk)/framework/p for p in ('PrivateHeaders','Headers')]
    paths += [vendor/p for p in ('.','private','include')]
    paths += [Path(sdk)/'usr/include']
    return [f'pthread_vendor_{unit}.o_CFLAGS_ADD='+' '.join('-I'+str(p) for p in paths)
            for unit in ('init','support','synch')]
