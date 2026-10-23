"""Monolithic, pinned Apple storage/HFS sources; original algorithms retained.

The initial block transport is immutable kernel-resident test media. DriverKit
and physical block-driver ioctls are not implemented by that transport.
"""
from pathlib import Path
import hashlib
import json
import re
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STORAGE = ('IOStorage', 'IOMedia', 'IOMediaBSDClient', 'IOBlockStorageDevice')


def replace(path, old, new, count=1):
    text = path.read_text(encoding='utf-8')
    if text.count(old) != count:
        raise ValueError('pinned storage source changed: ' + str(path))
    path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')


def install(storage, hfs, xnu):
    storage, hfs, xnu = Path(storage), Path(hfs), Path(xnu)
    target = xnu/'iokit/ums512_storage'
    target.mkdir()
    vendor = target/'vendor'
    vendor.mkdir()
    headers = target/'include/IOKit/storage'
    headers.mkdir(parents=True)
    for path in storage.glob('*.h'):
        shutil.copyfile(path, headers/path.name)
    for name in STORAGE:
        shutil.copyfile(storage/(name+'.cpp'), vendor/(name+'.cpp'))
    # The selected transport is IOStorage, not IOBlockStorageDriver. These four
    # optional hardware-driver ioctls already fail ENOTTY for such a provider.
    # Preserve the real BSD bridge, read/write/strategy/bounds/open/ioctl paths.
    path = vendor/'IOMediaBSDClient.cpp'
    text = path.read_text()
    for name in ('DKIOCEJECT', 'DKIOCFORMAT', 'DKIOCGETFORMATCAPACITIES', 'DKIOCREQUESTIDLE'):
        pattern = r'(        case '+name+r':[^\n]*\n        \{\n)(.*?)(\n        \} break;)'
        text, count = re.subn(pattern, r'\1#if !defined(UMS512_IMMUTABLE_MEDIA)\n\2\n#else\n            error = ENOTTY;\n#endif\3', text, flags=re.S)
        if count != 1:
            raise ValueError('original storage ioctl boundary changed: '+name)
    text = text.replace('#include <IOKit/storage/IOBlockStorageDriver.h>',
                        '/* This transport has no IOBlockStorageDriver provider. */')
    path.write_text(text, encoding='utf-8', newline='\n')
    prefix = '''/* Original external-kernel-extension header context. */
#undef BSD_KERNEL_PRIVATE
#undef MACH_KERNEL_PRIVATE
#undef MACH_KERNEL
#define XNU_KERNEL_PRIVATE 1
#include <string.h>
#ifndef XNU_USE_CHK_BUILTIN
#error Genuine XNU string fortify header required
#endif
#include <TargetConditionals.h>
'''
    for name in STORAGE:
        (target/(name+'.cpp')).write_text(prefix+'#define UMS512_IMMUTABLE_MEDIA 1\n'+
                                       '#include "vendor/'+name+'.cpp"\n', newline='\n')
    for name in ('LICENSE', 'APPLE_LICENSE'):
        if (storage/name).is_file():
            shutil.copyfile(storage/name, vendor/name)
    shutil.copyfile(ROOT/'xnu/platform/ums512/QemuRootStorage.cpp', target/'QemuRootStorage.cpp')
    with (xnu/'iokit/conf/files').open('a', newline='\n') as stream:
        for name in (*STORAGE, 'QemuRootStorage'):
            stream.write(f'\niokit/ums512_storage/{name}.cpp\toptional ums512\n')
        stream.write('\niokit/ums512_storage/root_image.s\toptional ums512\n')
    # Source list is taken from the genuine HFS kext target, not its userspace
    # livefiles implementation or test tools.
    project = (hfs/'hfs.xcodeproj/project.pbxproj').read_text()
    phase = project.split('FB20E0DB1AE950C200CEBE7B /* Sources */ = {', 1)[1].split('runOnlyForDeploymentPostprocessing', 1)[0]
    units = re.findall(r'/\* (\w+\.(?:c|cpp)) in Sources \*/', phase)
    if len(units) != 39 or len(set(units)) != 39:
        raise ValueError('pinned HFS kernel source phase changed')
    dest = xnu/'bsd/ums512_hfs'
    dest.mkdir()
    for directory in ('core', 'hfs_encodings'):
        shutil.copytree(hfs/directory, dest/directory)
    for name in ('LICENSE', 'APPLE_LICENSE'):
        if (hfs/name).is_file():
            shutil.copyfile(hfs/name, dest/name)
    # Keep actual CONFIG_PROTECT and its real access checks. No fake AKS header
    # or success provider is installed. The actual SDK dependency is probed.
    prefix += '#include "core/kext-config.h"\n#if !CONFIG_PROTECT\n#error Content protection must remain enabled\n#endif\n'
    for unit in units:
        (dest/unit).write_text(prefix+f'#include "core/{unit}"\n', newline='\n')
    # In the monolithic build this is not a separately loaded/unloadable kext.
    # Retain real mount counters while omitting only dynamic kext self-retains.
    for call in ('OSKextRetainKextWithLoadTag(OSKextGetCurrentLoadTag());',
                 'OSKextReleaseKextWithLoadTag(OSKextGetCurrentLoadTag());'):
        replace(dest/'core/hfs_vfsops.c', call, '/* Built into the kernel: no dynamic kext load tag. */')
    # Real registration methods are called explicitly, in the original VFS init
    # stage. No IOKit service is impersonated and no automatic success returned.
    replace(dest/'core/hfs_iokit.cpp', 'int hfs_is_ejectable(const char *cdev_name)', '''extern "C" void ums512_hfs_register(void)
{
    hfs_converterinit();
    com_apple_filesystems_hfs *fs = new com_apple_filesystems_hfs;
    if (!fs || !fs->init() || !fs->start(nullptr)) {
        panic("QEMU HFS: real filesystem registration failed");
    }
    /* Lifetime equals the built-in filesystem; no dynamic unload. */
}

int hfs_is_ejectable(const char *cdev_name)''')
    replace(dest/'core/hfs_iokit.cpp', '#include "hfs_cnode.h"',
            '#include "hfs_cnode.h"\n#include "../hfs_encodings/hfs_encodings_internal.h"')
    replace(dest/'core/hfs_readwrite.c', '\tswitch (ap->a_command) {', '''\tswitch (ap->a_command) {
    case FSIOC_KERNEL_ROOTAUTH: {
        extern int ums512_qemu_hfs_root_auth(dev_t, int, int);
        return ums512_qemu_hfs_root_auth(hfsmp->hfs_raw_dev, vnode_isvroot(vp),
                                        vfs_isrdonly(HFSTOVFS(hfsmp)));
    }
''')
    for unit in ('hfs_encodings.c', 'hfs_encodinghint.c'):
        units.append(unit)
        (dest/unit).write_text(prefix+'#define hfs_allocated ums512_hfs_encodings_allocated\n'+
                              f'#include "hfs_encodings/{unit}"\n', newline='\n')
    with (xnu/'bsd/conf/files').open('a', newline='\n') as stream:
        for unit in units:
            stream.write(f'\nbsd/ums512_hfs/{unit}\toptional ums512\n')
    (target/'source-units.json').write_text(json.dumps({'hfs': units, 'storage': STORAGE}, indent=2)+'\n')


def flags(xnu, sdk, exported):
    xnu, sdk, exported = Path(xnu), Path(sdk), Path(exported)
    framework = Path('System/Library/Frameworks/Kernel.framework')
    paths = [xnu/'iokit/ums512_storage/include', xnu/'libkern']
    paths += [exported/framework/p for p in ('PrivateHeaders', 'Headers')]
    paths += [xnu.parent/'xnu.obj/EXPORT_HDRS/osfmk', xnu/'osfmk']
    paths += [sdk/framework/p for p in ('PrivateHeaders', 'Headers')]
    paths += [xnu/'bsd/ums512_hfs', xnu/'bsd/ums512_hfs/core']
    units = json.loads((xnu/'iokit/ums512_storage/source-units.json').read_text())
    args = ' '.join('-I'+shlex.quote(str(p)) for p in paths)
    return [Path(unit).stem+'.o_CFLAGS_ADD='+args
            for unit in (*units['hfs'], *(n+'.cpp' for n in (*STORAGE, 'QemuRootStorage')))]


def image(xnu):
    """Format only a newly created regular file inside this isolated build tree."""
    xnu = Path(xnu).resolve()
    xnu.relative_to((ROOT/'out').resolve())
    target = xnu/'iokit/ums512_storage'
    disk = target/'root.hfs'
    with disk.open('xb') as stream:
        stream.truncate(16*1024*1024)
    if disk.is_symlink() or not disk.is_file() or disk.resolve().parent != target:
        raise ValueError('unsafe test filesystem destination')
    subprocess.run(['/sbin/newfs_hfs', '-v', 'RMXQemuRoot', '-s', '32768', str(disk)],
                   check=True, timeout=60, capture_output=True)
    data = disk.read_bytes()
    if len(data) != 16*1024*1024 or data[1024:1026] != b'H+':
        raise ValueError('newfs_hfs did not produce the requested plain HFS+ volume')
    sha = hashlib.sha256(data).digest()
    (target/'root_image.h').write_text('/* Per-build, controlled data-only root trust anchor. */\n'+
        '#define RMX_ROOT_BYTES '+str(len(data))+'ULL\n'+
        'static const unsigned char root_sha256[32] = {'+','.join(str(b) for b in sha)+'};\n', newline='\n')
    (target/'root_image.s').write_text('.section __DATA_CONST,__const\n.p2align 14\n'+
        '.globl _ums512_root_image\n_ums512_root_image:\n.incbin "'+str(disk)+'"\n', newline='\n')
    return {'bytes':len(data), 'sha256':sha.hex(), 'format':'HFS+', 'content':'empty owned data-only volume',
            'embedded_in_kernel':True, 'readonly':True, 'apple_trust':False}
