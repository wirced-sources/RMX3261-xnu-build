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
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STORAGE = ('IOStorage', 'IOMedia', 'IOMediaBSDClient', 'IOBlockStorageDevice')


def replace(path, old, new, count=1):
    text = path.read_text(encoding='utf-8')
    if text.count(old) != count:
        raise ValueError('pinned storage source changed: ' + str(path))
    path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')


def modernize_quota_prototypes(path):
    """Only join K&R parameter declarations; keep every original type/body."""
    text=path.read_text()
    pattern=r'^([A-Za-z_][\w \t*]*\bhfs_\w*|hfs_\w+)\(([\w, \t]+)\)\n((?:[ \t]+[^(){};\n]+;\n)+)\{'
    def convert(match):
        names=[name.strip() for name in match[2].split(',')]
        declarations={}
        for line in match[3].splitlines():
            declaration=re.sub(r'\bregister\s+','',line.strip().removesuffix(';'))
            name=re.search(r'(\w+)$',declaration)
            if not name or name[1] in declarations:
                raise ValueError('unexpected quota parameter declaration')
            declarations[name[1]]=declaration
        if set(names)!=set(declarations):
            raise ValueError('quota definition/prototype parameter mismatch')
        return match[1]+'('+', '.join(declarations[name] for name in names)+')\n{'
    text,count=re.subn(pattern,convert,text,flags=re.M)
    if not count:
        raise ValueError('expected original K&R quota definitions absent')
    path.write_text(text,encoding='utf-8',newline='\n')


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
    replace(path,'register UInt64','UInt64',count=2)
    replace(path,'// Reprioritize a read or write request.',
            'if (request.tier>3) { error=EINVAL; break; }\n\n            // Reprioritize a read or write request.')
    for value in ('request.tier','bufattr_throttled(attributes.bufattr)'):
        replace(path,'DK_TIER_TO_PRIORITY('+value+')',
                'static_cast<IOStoragePriority>(DK_TIER_TO_PRIORITY('+value+') & UINT8_MAX)')
    prefix = '''/* Original external-kernel-extension header context. */
#undef BSD_KERNEL_PRIVATE
#undef MACH_KERNEL_PRIVATE
#undef MACH_KERNEL
#define XNU_KERNEL_PRIVATE 1
#ifndef _FORTIFY_SOURCE_STRICT
#define _FORTIFY_SOURCE_STRICT 1
#endif
#include <string.h>
#if !XNU_USE_CHK_BUILTIN(memcpy) || !_FORTIFY_SOURCE_STRICT
#error Genuine XNU string fortify header required
#endif
#include <libkern/sysctl.h>
#undef XNU_KERNEL_PRIVATE
/* Original external-kext type visibility; strict string macros stay active. */
#include <TargetConditionals.h>
'''
    for name in STORAGE:
        # IOUserClient's native statistics header needs the full core OSKext
        # declarations. Compile that one built-in provider in native context,
        # preserving IOKITSTATS and its real privilege checks.
        context='#include <TargetConditionals.h>\n' if name=='IOBlockStorageDevice' else prefix
        (target/(name+'.cpp')).write_text(context+'#define UMS512_IMMUTABLE_MEDIA 1\n'+
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
    absent=[unit for unit in units if not (hfs/'core'/unit).is_file()]
    if absent!=['hfs_key_roll.c']:
        raise ValueError('unexpected unpublished HFS sources: '+str(absent))
    units.remove('hfs_key_roll.c')
    dest = xnu/'bsd/ums512_hfs'
    dest.mkdir()
    for directory in ('core', 'hfs_encodings'):
        shutil.copytree(hfs/directory, dest/directory)
    for name in ('LICENSE', 'APPLE_LICENSE'):
        if (hfs/name).is_file():
            shutil.copyfile(hfs/name, dest/name)
    # Keep actual CONFIG_PROTECT and all access checks. The real SDK has no AKS
    # header. Use native XNU buffer types and explicitly internal credentials;
    # no invented Apple ABI/service table crosses the platform-function API.
    for suffix in ('.h','.inc'):
        name='ums512_hfs_keys'+suffix
        shutil.copyfile(ROOT/'xnu/platform/ums512'/name,dest/'core'/name)
    replace(dest/'core/hfs_iokit.h','#include <AppleKeyStore/AppleKeyStoreFSServices.h>',
            '#include "ums512_hfs_keys.h"')
    for unit in ('hfs_iokit.h','hfs_iokit.cpp','hfs_cprotect.c'):
        path=dest/'core'/unit
        text=path.read_text()
        for old,new in (('struct aks_cred_s','struct rmx_hfs_key_cred'),
                        ('aks_cred_t','rmx_hfs_key_cred_t'),
                        ('struct aks_raw_key_s','cp_raw_key_s'),('aks_raw_key_t','cp_raw_key_t'),
                        ('struct aks_wrapped_key_s','cp_wrapped_key_s'),('aks_wrapped_key_t','cp_wrapped_key_t'),
                        ('AKS_RAW_KEY_WRAPPEDKEY','CP_RAW_KEY_WRAPPEDKEY')):
            text=text.replace(old,new)
        path.write_text(text,encoding='utf-8',newline='\n')
    for field in ('inode','pid','uid','key_revision'):
        replace(dest/'core/hfs_cprotect.c','access->'+field,'access->context.'+field)
    replace(dest/'core/hfs_cprotect.c','access_in.key_revision','access_in.context.key_revision')
    path=dest/'core/hfs_iokit.cpp'
    text=path.read_text()
    marker='// Interface with AKS'
    if text.count(marker)!=1 or not text.rstrip().endswith('return ks->backup_key(access, wrapped_key_in, wrapped_key_out);\n}'):
        raise ValueError('original unavailable key service boundary changed')
    path.write_text(text.split(marker)[0]+'#include "ums512_hfs_keys.inc"\n',encoding='utf-8',newline='\n')
    # HFS MacOS source normally leaves protection off in its external config.
    # The native profile enables it: include the genuine private declarations
    # in units which previously depended on iPhoneOS transitive includes.
    prefix += '''#include "core/kext-config.h"
#if !CONFIG_PROTECT
#error Content protection must remain enabled
#endif
#if HFS_CONFIG_KEY_ROLL
#error This published HFS tree has no key-roll implementation
#endif
#define sysctlbyname kernel_sysctlbyname /* Genuine XNU kext export alias. */
#include "core/hfs_cprotect.h"
'''
    for unit in units:
        checks=''
        if unit=='hfs_catalog.c':
            checks='''_Static_assert(sizeof(FndrDirInfo)==16 && sizeof(FndrFileInfo)==16 && sizeof(FndrOpaqueInfo)==16,"Finder field sizes");
_Static_assert(__builtin_offsetof(HFSPlusCatalogFolder,finderInfo)==__builtin_offsetof(HFSPlusCatalogFolder,userInfo)+16,"Folder Finder adjacency");
_Static_assert(__builtin_offsetof(HFSPlusCatalogFile,finderInfo)==__builtin_offsetof(HFSPlusCatalogFile,userInfo)+16,"File Finder adjacency");
'''
        (dest/unit).write_text(prefix+f'#include "core/{unit}"\n'+checks, newline='\n')
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
    replace(dest/'core/hfs_search.c','vp->v_type == VDIR','vnode_vtype(vp) == VDIR')
    replace(dest/'core/hfs_search.c','hfs_vnop_search(ap)\n\tstruct vnop_searchfs_args *ap; /*',
            'hfs_vnop_search(struct vnop_searchfs_args *ap)\n\t/*')
    modernize_quota_prototypes(dest/'core/hfs_quota.c')
    replace(dest/'core/hfs_cprotect.h','cp_key_class_t *class);','cp_key_class_t *class_out);')
    replace(dest/'core/hfs_vfsops.c','(cp_lock_state_t)data','(cp_lock_state_t)(uintptr_t)data')
    replace(dest/'core/hfs_vnops.c','fp->ff_size <= hfsmp->hfs_defrag_max',
            'fp->ff_size >= 0 && (uint64_t)fp->ff_size <= hfsmp->hfs_defrag_max')
    path=dest/'core/hfs_attrlist.c'
    text=path.read_text()
    for name in ('readdirattr','getattrlistbulk'):
        pattern=r'hfs_vnop_'+name+r'\(ap\)\n\s+struct vnop_'+name+r'_args /\* \{.*?\} \*/ \*ap;'
        text,count=re.subn(pattern,'hfs_vnop_'+name+'(struct vnop_'+name+'_args *ap)',text,flags=re.S)
        if count!=1:
            raise ValueError('legacy HFS vnode signature changed')
    path.write_text(text,encoding='utf-8',newline='\n')
    # The public tree does not define its private CP_ROOT_CRYPTOG1 flag or
    # publish file-key services. Refuse every protected-volume mount before
    # interpreting that unavailable metadata; never guess a crypto generation.
    path=dest/'core/hfs_vfsutils.c'
    text=path.read_text()
    start=text.index('\t/* At this point, if the mount point flag is set, we can enable it. */')
    end=text.index('\t/*\n\t * Establish a metadata allocation zone.',start)
    text=text[:start]+'''\t/* Missing real file-key provider: all protected volumes fail closed. */
\tif (vfs_flags(hfsmp->hfs_mp) & MNT_CPROTECT) {
\t\tretval = ENXIO;
\t\tgoto ErrorExit;
\t}

'''+text[end:]
    path.write_text(text,encoding='utf-8',newline='\n')
    # Aligned output temporaries preserve all original allocator results while
    # avoiding uint32_t pointers to packed on-disk extent members.
    path=dest/'core/VolumeAllocation.c'
    text=path.read_text()
    pattern=r'(err = |return )(BlockFind\w+)\(([^;]*&extent->startBlock[^;]*&extent->blockCount[^;]*)\);'
    def aligned(match):
        args=match[3].replace('&extent->startBlock','&rmx_start').replace('&extent->blockCount','&rmx_count')
        returning=match[1]=='return '
        return '{ uint32_t rmx_start=extent->startBlock,rmx_count=extent->blockCount;\n'+\
               ('OSErr rmx_result = ' if returning else 'err = ')+match[2]+'('+args+');\n'+\
               'extent->startBlock=rmx_start; extent->blockCount=rmx_count; '+\
               ('return rmx_result; ' if returning else '')+'}'
    text,count=re.subn(pattern,aligned,text)
    if count!=9 or '&extent->' in text:
        raise ValueError('packed HFS allocator output sites changed: '+str(count))
    path.write_text(text,encoding='utf-8',newline='\n')
    replace(dest/'core/hfs_readwrite.c','iotypeflag = (uint32_t) ap->a_data;',
            'iotypeflag = (uint32_t)(uintptr_t) ap->a_data;')
    # Finder fields are two adjacent 16-byte records. Keep strict fortify by
    # copying each actual object, not asserting that a16-byte field is32 bytes.
    path=dest/'core/hfs_catalog.c'
    text=path.read_text()
    pattern=r'bcopy\(([^;\n]+), &([\w.>-]+)userInfo, 32\);'
    text,count=re.subn(pattern,r'bcopy(\1, &\2userInfo, 16);\n\tbcopy((const unsigned char *)(\1)+16, &\2finderInfo, 16);',text)
    if count!=4:
        raise ValueError('HFS Finder metadata copy sites changed: '+str(count))
    text=text.replace('bcopy(&crp->userInfo, attrp->ca_finderinfo, 32);',
        'bcopy(&crp->userInfo, attrp->ca_finderinfo, 16);\n'+
        '\tbcopy(&crp->finderInfo, attrp->ca_finderinfo+16, 16);')
    path.write_text(text,encoding='utf-8',newline='\n')
    replace(dest/'core/hfs_readwrite.c', '\tswitch (ap->a_command) {', '''\tswitch (ap->a_command) {
    case FSIOC_KERNEL_ROOTAUTH: {
        extern int ums512_qemu_hfs_root_auth(dev_t, int, int);
        return ums512_qemu_hfs_root_auth(hfsmp->hfs_raw_dev, vnode_isvroot(vp),
                                        vfs_isrdonly(HFSTOVFS(hfsmp)));
    }
''')
    for unit in ('hfs_encodings.c', 'hfs_encodinghint.c'):
        units.append(unit)
        (dest/unit).write_text(prefix+'#include "hfs_encodings/hfs_encodings_internal.h"\n'+
                              '#define hfs_allocated ums512_hfs_encodings_allocated\n'+
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
    result=[]
    for unit in (*units['hfs'], *(n+'.cpp' for n in (*STORAGE, 'QemuRootStorage'))):
        obj=Path(unit).stem+('.cpo' if unit.endswith('.cpp') else '.o')
        # Full native context also requires native, unstripped Mach headers;
        # exported kext mach/vm_types.h intentionally lacks OSKext VM accounts.
        includes=('-I'+shlex.quote(str(paths[0]))) if unit=='IOBlockStorageDevice.cpp' else args
        result.append(obj+'_CFLAGS_ADD='+includes+' -Wall -Wextra -Wno-missing-field-initializers'+
                      ' -Wno-error=unused-parameter -Wno-error=deprecated-declarations'+
                      ' -Wno-error=nullability-completeness -Wno-error=nullability-completeness-on-arrays')
        # Restore the original module warning profile (Wall/W), retaining
        # Werror, typed allocators, fortify, stack checks and all native ABI flags.
        result.append(obj+'_CFLAGS_RM=-Weverything')
    return result


def validate_image(data):
    """Embedding guard from pinned hfs_format.h; not an HFS fsck substitute."""
    if len(data)<4096 or len(data)>32*1024*1024 or len(data)%512:
        raise ValueError('root image size outside bounded raw-sector profile')
    if data[1024:1028]!=b'H+\x00\x04':
        raise ValueError('root image is not unpartitioned HFS+ version4')
    attrs=struct.unpack_from('>I',data,1028)[0]
    block_size,blocks,free=struct.unpack_from('>III',data,1064)
    if block_size<512 or block_size>65536 or block_size&(block_size-1) or blocks*block_size!=len(data) or free>blocks:
        raise ValueError('invalid HFS allocation geometry')
    if not attrs&(1<<8) or attrs&((1<<11)|(1<<14)):
        raise ValueError('test root is not cleanly unmounted/consistent')
    if attrs&(1<<30):
        raise ValueError('encrypted test root requires an actual file-key provider')
    alt=len(data)-1024
    if data[alt:alt+4]!=data[1024:1028] or data[alt+40:alt+48]!=data[1064:1072]:
        raise ValueError('alternate HFS volume geometry mismatch')
    occupied=set(range((1536+block_size-1)//block_size)) | set(range(alt//block_size,blocks))
    for offset in (112,192,272):
        length,_,allocated=struct.unpack_from('>QII',data,1024+offset)
        if not length or not allocated or length>allocated*block_size:
            raise ValueError('missing/out-of-bounds required HFS metadata fork')
        total=0
        for i in range(8):
            start,count=struct.unpack_from('>II',data,1024+offset+16+8*i)
            if count:
                if not start or start>=blocks or count>blocks-start:
                    raise ValueError('HFS metadata extent outside image')
                span=set(range(start,start+count))
                if occupied&span:
                    raise ValueError('overlapping HFS metadata extents')
                occupied.update(span)
                total+=count
        if total!=allocated:
            raise ValueError('test metadata fork requires unsupported overflow extents')
    return {'block_bytes':block_size,'allocation_blocks':blocks,'attributes':attrs}


def image(xnu):
    """Create only owned test image files; never pass a device node to a formatter.

    macOS newfs_hfs accepts device basenames, not regular-file destinations.
    hdiutil owns its temporary image attachment and detaches it automatically;
    no host mount, device path, sudo, physical disk or user files are supplied.
    """
    xnu = Path(xnu).resolve()
    xnu.relative_to((ROOT/'out').resolve())
    target = xnu/'iokit/ums512_storage'
    staging=target/'root-content'
    staging.mkdir()
    (staging/'dev').mkdir()
    (staging/'sbin').mkdir()
    (staging/'root-proof.txt').write_text('Owned QEMU laboratory data; no Apple userland.\n')
    dmg, raw = target/'root.dmg', target/'root.cdr'
    if dmg.exists() or raw.exists():
        raise ValueError('refusing to overwrite a root image')
    for command in (
        ['/usr/bin/hdiutil','create','-quiet','-size','16m','-fs','HFS+',
         '-volname','RMXQemuRoot','-layout','NONE','-srcfolder',str(staging),'-format','UDRW',str(dmg)],
        ['/usr/bin/hdiutil','convert','-quiet',str(dmg),'-format','UDTO','-o',str(raw)]):
        result=subprocess.run(command, timeout=120, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('owned HFS image creation failed: '+(result.stdout+result.stderr)[-4000:])
    data = raw.read_bytes()
    geometry=validate_image(data)
    disk=target/'root.hfs'
    with disk.open('xb') as stream:
        stream.write(data)
    sha = hashlib.sha256(data).digest()
    (target/'root_image.h').write_text('/* Per-build, controlled data-only root trust anchor. */\n'+
        '#define RMX_ROOT_BYTES '+str(len(data))+'ULL\n'+
        'static const unsigned char root_sha256[32] = {'+','.join(str(b) for b in sha)+'};\n', newline='\n')
    (target/'root_image.s').write_text('.section __DATA_CONST,__const\n.p2align 14\n'+
        '.globl _ums512_root_image, _ums512_root_image_end\n_ums512_root_image:\n.incbin "'+str(disk)+'"\n'+
        '_ums512_root_image_end:\n', newline='\n')
    return {'bytes':len(data), 'sha256':sha.hex(), 'format':'HFS+', 'content':'owned /dev, /sbin and root-proof.txt; no executable',
            'geometry':geometry, 'embedded_in_kernel':True, 'readonly':True, 'apple_trust':False}
