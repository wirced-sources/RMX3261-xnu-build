"""Offline physical-XNU components and one-shot arm_init/courier boot builder.

Reuses existing UMS512 handoff, CPU/RAM policy and genuine XNU source installer.
No USB driver is fabricated; arm_init RAM checkpoint is not hardware proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys

from build import ROOT, tool
from elf import ELF
from fdt import FDT
from xnu_build import FLAGS, facts, audit_object
from xnu_host import unix

DEFAULT=ROOT/'out/xnu-physical-v3'
PLATFORM=ROOT/'xnu/platform/ums512'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def install_progress(src):
    """Genuine hardware arm_init only; no replacement function or QEMU edits."""
    src=Path(src)
    p=src/'osfmk/arm/arm_init.c'
    text=p.read_text(encoding='utf-8')
    anchor='\tarm_slide_rebase_and_sign_image();'
    if text.count(anchor)!=1 or 'ums512_xnu_arm_init_checkpoint' in text:
        raise ValueError('unexpected/already patched genuine arm_init')
    header='#if UMS512_HARDWARE_TARGET\n#include <ums512/ums512_progress.h>\n#endif\n'
    at=text.index('#include')
    text=text[:at]+header+text[at:]
    text=text.replace(anchor,anchor+'\n#if UMS512_HARDWARE_TARGET\n'
                      '\tums512_xnu_arm_init_checkpoint(args);\n#endif',1)
    target=src/'osfmk/ums512';target.mkdir(parents=True,exist_ok=True)
    for name in ('ums512_progress.c','ums512_progress.h','ums512_progress_return.S'):
        shutil.copyfile(PLATFORM/name,target/('ums512_progress_return.s' if name.endswith('.S') else name))
    p.write_text(text,encoding='utf-8',newline='\n')


def display_facts(live, overlay, source_dir):
    """Explicit hardware allowlist; never export raw FDT/DCS/identifiers."""
    tree=FDT(Path(live).read_bytes())
    chosen=tree.nodes['/chosen'].props.get('bootargs',b'').rstrip(b'\0').decode('ascii')
    selected=[w.split('=',1)[1] for w in chosen.split() if w.startswith('lcd_name=')]
    if len(selected)!=1:raise ValueError('saved live FDT has ambiguous selected panel')
    geometry={}
    for compatible in ('sprd,display-processor','sprd,dsi-host','sprd,dsi-phy','sprd,sharkl5pro-musb'):
        nodes=[n for n in tree.nodes.values() if compatible in n.strings('compatible')]
        if len(nodes)!=1:raise ValueError('missing/ambiguous display/USB node')
        n=nodes[0];geometry[compatible]=dict(reg=[[hex(a),hex(b)] for a,b in tree.reg(n)],
                                            ip=n.strings('sprd,ip'),status=n.strings('status'))
    from m05_images import dtbo_summary
    raw=Path(overlay).read_bytes();table=dtbo_summary(raw)
    candidates=[]
    keys=('clock-frequency','hactive','vactive','hfront-porch','hback-porch','hsync-len',
          'vfront-porch','vback-porch','vsync-len')
    for entry in table['entries']:
        dt=FDT(raw[entry['offset']:entry['offset']+entry['bytes']])
        for path,n in dt.nodes.items():
            if path.startswith('/__') or path.rsplit('/',1)[-1]!=selected[0]:continue
            timings=[v for k,v in dt.nodes.items() if k.startswith(path+'/display-timings/') and 'hactive' in v.props]
            if len(timings)!=1:raise ValueError('ambiguous selected panel timings')
            timing={k:timings[0].cells(k)[0] for k in keys}
            if (timing['hactive'],timing['vactive'])!=(720,1600):raise ValueError('selected panel geometry changed')
            candidates.append(dict(name=selected[0],timings=timing,
                                   phy_bit_clock_raw=n.cells('sprd,phy-bit-clock'),
                                   init_command_bytes=len(n.props.get('sprd,initial-command',b'')),
                                   reset_sequence_bytes=len(n.props.get('sprd,reset-on-sequence',b''))))
    if len(candidates)!=1:raise ValueError('selected historical panel not unique in DTBO')
    lock=json.loads((ROOT/'docs/ums512-driver-sources.json').read_text())
    paths=['drivers/gpu/drm/sprd/sprd_dpu.c','drivers/gpu/drm/sprd/sprd_dsi.c','drivers/gpu/drm/sprd/dpu/dpu_r4p0.c']
    pins={v['path']:v['sha256'] for v in lock['files']}
    for p in paths:
        if sha(Path(source_dir)/p)!=pins[p]:raise ValueError('pinned Linux driver changed')
    return dict(source='saved live FDT + private DTBO + pinned public Linux source; NOT current hardware state',
                live_fdt_sha256=sha(live),overlay_sha256=sha(overlay),controllers=geometry,
                selected_historical_panel=candidates[0],source_hashes={p:pins[p] for p in paths},
                pipeline=['DPU r4p0','DSI r3p1','Megacores DPHY','selected panel DCS init','backlight'],
                blockers=['current selected panel/bootloader scanout ownership must match saved facts',
                          'DPU clocks/resets/QoS/IOMMU and framebuffer DMA mapping are not initialized by the RAM renderer',
                          'DSI/DPHY lane/PLL/reset/DCS/backlight lifecycle is not implemented in XNU',
                          'MUSB gadget/PHY/clock initialization and EP0 transport are not implemented in XNU'],
                display_mmio_performed=False,usb_transport_implemented=False)


def components(directory):
    directory.mkdir(parents=True)
    facts(directory)
    cc=tool('clang','CLANG')
    include=['-I',str(directory),'-I',str(ROOT/'shim/ums512'),'-I',str(PLATFORM)]
    entries={'loader':ROOT/'shim/ums512/xnu_loader.c','handoff':ROOT/'shim/ums512/handoff.S',
             'platform':PLATFORM/'platform.c','progress':PLATFORM/'ums512_progress.c','frame':PLATFORM/'ums512_frame.c'}
    result={}
    env=dict(os.environ,TMP=str(directory),TEMP=str(directory),TMPDIR=str(directory))
    for name,path in entries.items():
        out=directory/(name+'.o')
        subprocess.run([cc,'--target=aarch64-none-elf',*FLAGS,'-ffunction-sections','-fdata-sections',*include,'-c',str(path),'-o',str(out)],
                       check=True,env=env,timeout=30)
        result[name]=dict(bytes=out.stat().st_size,sha256=sha(out),**audit_object(out))
    combined=directory/'xnu-shim-component.o'
    subprocess.run([tool('ld.lld','LD_LLD'),'-r','--gc-sections','--undefined=ums512_xnu_load_and_enter',
                    '--undefined=ums512_xnu_validate_load',str(directory/'loader.o'),str(directory/'handoff.o'),
                    str(directory/'platform.o'),'-o',str(combined)],check=True,timeout=30)
    result['combined']=dict(bytes=combined.stat().st_size,sha256=sha(combined),**audit_object(combined))
    if result['combined']['undefined']:raise ValueError('undefined shim dependency')
    # Also compile the new genuine-XNU hook using Apple's object format.
    out=directory/'progress.macho.o'
    subprocess.run([cc,'--target=arm64-apple-macos11',*FLAGS,*include,'-c',str(entries['progress']),'-o',str(out)],
                   check=True,env=env,timeout=30)
    result['progress_macho']=dict(bytes=out.stat().st_size,sha256=sha(out),**audit_object(out,macho=True))
    return result


def build(out=DEFAULT):
    out=Path(out).resolve();out.relative_to((ROOT/'out').resolve())
    if out.exists():raise ValueError('new output directory required')
    a=components(out/'components');b=components(out/'repeat')
    if a!=b:raise ValueError('component builds not reproducible')
    display=display_facts(ROOT/'out/physical-m1/stock-02-preflight/live-fdt.bin',
                         ROOT/'private/boot_images/dtbo_a.img',ROOT/'out/ums512-target/sources')
    # Genuine XNU source-hook installation proof, without a costly Apple build.
    fixture=out/'hook-check/osfmk/arm';fixture.mkdir(parents=True)
    shutil.copyfile(ROOT/'out/ums512hw-native-ready/xnu/osfmk/arm/arm_init.c',fixture/'arm_init.c')
    install_progress(out/'hook-check')
    sources=['shim/ums512/xnu_loader.c','shim/ums512/xnu_loader.h','shim/ums512/handoff.S','shim/ums512/xnu_boot.h',
             'xnu/platform/ums512/platform.c','xnu/platform/ums512/platform.h','boards/ums512-hardware.json',
             'xnu/platform/ums512/ums512_progress.c','xnu/platform/ums512/ums512_progress.h',
             'xnu/platform/ums512/ums512_frame.c','xnu/platform/ums512/ums512_frame.h']
    report=dict(kind='UMS512 physical XNU components, NOT boot.img/MH_EXECUTE',components=a,reproducible=True,
                source_hashes={p:sha(ROOT/p) for p in sources},
                genuine_arm_init_hook_prepared=True,full_kernel_rebuilt=False,arm_init_executed=False,
                xnu_usb_proof=False,hardware_ready=False,flashable_image_emitted=False,
                display=display,blockers=['owner ROOT_A_WRITE_QUALIFIED receipt required first',
                    'new full UMS512HW Mach-O with arm_init hook must be built/retained on Apple CI',
                    'qualified live entry EL/cache/owned RAM and GIC/timer firmware contract missing',
                    'independent XNU USB transport not implemented; RAM checkpoint is not hardware proof'])
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report


def verify(out=DEFAULT):
    out=Path(out);p=json.loads((out/'manifest.json').read_text())
    names={k:k+'.o' for k in ['loader','handoff','platform','progress','frame']}
    names.update(combined='xnu-shim-component.o',progress_macho='progress.macho.o')
    for name,h in p['source_hashes'].items():
        if sha(ROOT/name)!=h:raise ValueError('source changed since component build')
    for k,name in names.items():
        for sub in ['components','repeat']:
            if sha(out/sub/name)!=p['components'][k]['sha256']:raise ValueError('component hash mismatch')
    if p['hardware_ready'] or p['xnu_usb_proof'] or p['flashable_image_emitted']:
        raise ValueError('unsupported physical readiness claim')
    return p


def m2_layout(data):
    """One conservative diagnostic window; runtime FDT revalidates exclusions."""
    from macho_kernel import audit, mapping, bootstrap_coverage
    from ums512_handoff import make_adt
    from ums512_target import profile, ram_windows, extent
    report=audit(data,zero_slide_local_relocations=True)
    board=json.loads((ROOT/'boards/ums512-hardware.json').read_text())
    history=json.loads((ROOT/'docs/m05-memory.json').read_text())['regions']
    base,size=0xa0000000,0x08000000
    if not any(a<=base and base+size<=b for a,b in map(extent,ram_windows(board,history))):
        raise ValueError('diagnostic window intersects saved exclusions')
    seg=[s for s in report['segments'] if s['initprot'] and s['vmsize']]
    va=min(s['vmaddr'] for s in seg)&-0x2000000
    low=min(s['vmaddr'] for s in seg)-va+base
    end=max(s['vmaddr']+s['vmsize'] for s in seg)-va+base
    align=lambda n:(n+0x3fff)&-0x4000
    adt_pa=align(end);args_pa=adt_pa+0x4000;stack_pa=args_pa+0x4000
    log_pa=stack_pa+0x10000;top=log_pa+0x4000
    regions=dict(Kernel=(low,end),DeviceTree=(adt_pa,adt_pa+1),BootArgs=(args_pa,args_pa+736),
                 BootStack=(stack_pa,stack_pa+0x10000),BootDiag=(log_pa,log_pa+272))
    p=profile(board)
    # No randomness-dependent subsystem runs before this one-shot checkpoint.
    # A diagnostic seed is explicitly NOT qualified entropy for a running OS.
    adt=make_adt(p,(base,base+size),regions,0,0,bytes(64))
    regions['DeviceTree']=(adt_pa,adt_pa+len(adt))
    adt=make_adt(p,(base,base+size),regions,0,0,bytes(64))
    if len(adt)>0x4000:raise ValueError('ADT too large')
    plan=mapping(report,base,va,size,adt_pa,len(adt),args_pa,top)
    coverage=bootstrap_coverage(base,va,size,low,[(a,b-a) for a,b in regions.values()],(base,size))
    args=bytearray(736)
    struct.pack_into('<HH4x4Q',args,0,2,2,va,base,size,top)
    struct.pack_into('<QI',args,96,plan['deviceTreeP'],len(adt))
    struct.pack_into('<Q',args,728,size)
    return dict(report=report,base=base,size=size,va=va,top=top,regions=regions,
                plan=plan,coverage=coverage),adt,bytes(args)


def compile_m2(directory, layout, adt, args, tag, original, macho_offset, macho_bytes, initrd_bytes):
    from boot_a_probe import image_info
    directory.mkdir(parents=True)
    _,memory,flags=image_info(original)
    stub=(memory+0x3fff)&-0x4000
    regs=layout['regions'];base,size=layout['base'],layout['size']
    ext=lambda a,b:'{'+f'{a}ULL,{b-a}ULL'+'}'
    # asm includes only integer defines. The C template reuses the actual ABI.
    defines=dict(M2_STUB_OFFSET=stub,M2_RAM_BASE=base,M2_RAM_SIZE=size,
                 M2_IMAGE_BYTES=0x1e80000,
                 M2_ENTRY_PA=layout['plan']['entry_pa'],M2_MACHO_OFFSET=macho_offset,
                 M2_MACHO_BYTES=macho_bytes,M2_INITRD_BYTES=initrd_bytes,
                 M2_LINUX_WORD=struct.unpack_from('<I',original)[0],M2_LINUX_SIZE=memory)
    head=''.join(f'#define {k} {v:#x}\n' for k,v in defines.items())
    head+=f'#define M2_TAG "{tag}"\n#define M2_PENDING "m1probe={tag}-P"\n'
    fields=[ext(base,base+size),*[ext(*regs[k]) for k in ('Kernel','BootArgs','DeviceTree','BootStack','BootDiag')],
            f'{layout["va"]}ULL',f'{layout["top"]}ULL','16384']
    head+='#ifndef __ASSEMBLER__\nstatic const struct ums512_plan m2_plan={'+','.join(fields)+'};\n'
    head+='static unsigned char m2_adt[]={'+','.join(map(str,adt))+'};\n'
    va,top=layout['va'],layout['top']
    head+=('static const struct xnu_boot_args m2_args_template={.revision=2,.version=2,'
           f'.virt_base={va}ULL,.phys_base={base}ULL,.mem_size={size}ULL,.mem_size_actual={size}ULL,'
           f'.top_of_kernel_data={top}ULL,.device_tree={layout["plan"]["deviceTreeP"]}ULL,.device_tree_length={len(adt)}'+'};\n')
    # Properties are unambiguous CPU timebase leaves in our generated ADT.
    offsets=[];at=0
    while (at:=adt.find(b'timebase-frequency\0',at))>=0:
        offsets.append(at+36);at+=36
    if len(offsets)!=8:raise ValueError('unexpected ADT CPU timebase layout')
    head+='static const unsigned m2_frequency_offsets[]={'+','.join(map(str,offsets))+'};\n#endif\n'
    (directory/'m2_config.h').write_text(head,encoding='ascii')
    from xnu_build import facts
    facts(directory)
    paths=[ROOT/'shim/ums512/xnu_entry.S',ROOT/'shim/ums512/xnu_entry.c',ROOT/'shim/ums512/xnu_loader.c',
           ROOT/'shim/ums512/handoff.S',PLATFORM/'platform.c']
    objects=[]
    for i,path in enumerate(paths):
        obj=directory/f'{i}.o';objects.append(obj)
        subprocess.run([tool('clang','CLANG'),'--target=aarch64-none-elf',*FLAGS,'-fpie',
            '-ffunction-sections','-fdata-sections','-I',str(directory),'-I',str(ROOT/'shim/ums512'),
            '-I',str(PLATFORM),'-c',str(path),'-o',str(obj)],check=True,timeout=30)
    ld=directory/'link.ld'
    ld.write_text('ENTRY(m2_entry)\nSECTIONS { . = '+str(stub)+'; .text : { *(.text.entry) *(.text*) } '
                  '.rodata : ALIGN(16) { *(.rodata*) } .data : ALIGN(16) { *(.data*) } '
                  '.bss : ALIGN(16) { *(.bss*) *(COMMON) } m2_end = .; /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) } }\n')
    elf=directory/'loader.elf'
    subprocess.run([tool('ld.lld','LD_LLD'),'--build-id=none','--no-undefined','--gc-sections','-T',str(ld),
                    *map(str,objects),'-o',str(elf)],check=True,timeout=30)
    parsed=ELF(elf.read_bytes());sym=parsed.symbols()
    if parsed.entry!=stub or any(s==0 for _,s in sym.values()):raise ValueError('entry or unresolved shim symbol')
    blob=directory/'loader.bin'
    subprocess.run([tool('llvm-objcopy','LLVM_OBJCOPY'),'-O','binary',str(elf),str(blob)],check=True,timeout=30)
    code=blob.read_bytes();image_size=(sym['m2_end'][0]+4095)&-4096
    if image_size>0x1e80000:raise ValueError('expanded Image would reach escrow/FDT')
    wrapped=bytearray(original+bytes(image_size-len(original)))
    wrapped[stub:stub+len(code)]=code
    struct.pack_into('<I',wrapped,0,0x14000000|(stub>>2))
    struct.pack_into('<Q',wrapped,16,image_size)
    # m2_main needs the final extent, including .bss, to exclude from target.
    # A fixed bound covers the entire <=30.5MiB source Image, no circular build.
    if sym['m2_linux_return'][0]+0x80080000>=0x81f00000:raise ValueError('return outside reviewed source range')
    (directory/'kernel-xnu.Image').write_bytes(wrapped)
    return bytes(wrapped),dict(stub_offset=stub,image_bytes=image_size,loader_bytes=len(code),
                               entry_offset=parsed.entry,return_offset=sym['m2_linux_return'][0],
                               symbols={k:v[0] for k,v in sym.items() if k.startswith('m2_')})


def build_m2(kernel, record, out):
    """Offline diagnostic container using a retained genuine native kernel."""
    import secrets
    from macho_kernel import audit
    from xnu_kernel_qemu import symbols
    from m1_standalone import sources, compile_init, initramfs, unpack_cpio, cpio, KEY
    from boot_a_probe import repack_v2, diagnostic_footer, token
    import gzip, stat
    out=Path(out).resolve();out.relative_to((ROOT/'out').resolve())
    if out.exists():raise ValueError('fresh output required')
    data=Path(kernel).read_bytes();proof=json.loads(Path(record).read_text())
    report=audit(data,zero_slide_local_relocations=True);sym=symbols(data)
    if not (proof.get('kernel_linked') and proof.get('sha256')==report['sha256'] and
            proof.get('source_commit')=='1b191cb58250d0705d8a51287127505aa4bc0789' and
            proof.get('diagnostic_observer_included') is False and
            proof.get('hardware_backend_audit',{}).get('qemu_backends_absent')):
        raise ValueError('genuine retained hardware kernel/provenance required')
    required=['__start','_arm_init','_ums512_xnu_arm_init_checkpoint','_ums512_xnu_return_to_linux']
    if any(n not in sym for n in required):raise ValueError('genuine arm_init checkpoint/return symbols missing')
    # Prove the actual arm_init code calls the actual checkpoint, no replacement.
    import capstone
    owner=next(s for s in report['segments'] if s['vmaddr']<=sym['_arm_init']<s['vmaddr']+s['filesize'])
    off=owner['fileoff']+sym['_arm_init']-owner['vmaddr']
    md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    calls=[i.address for i in md.disasm(data[off:off+2048],sym['_arm_init'])
           if i.mnemonic=='bl' and int(i.op_str.lstrip('#'),16)==sym['_ums512_xnu_arm_init_checkpoint']]
    if not calls:raise ValueError('no direct checkpoint call in genuine arm_init')
    a,b,linux,capabilities=sources();layout,adt,args=m2_layout(data)
    out.mkdir(parents=True);tag=secrets.token_hex(16)
    binary=compile_init(tag,out)
    entries=unpack_cpio(gzip.decompress(initramfs(binary)))
    members=[(n,v['mode'],v['data'],v['major'],v['minor']) for n,v in entries.items()]
    rd=cpio(members+[('xnu.macho',stat.S_IFREG|0o400,data,0,0)])
    offset=rd.find(data)
    if offset<0 or rd.find(data,offset+1)!=-1:raise ValueError('Mach-O cpio payload ambiguous')
    # Entry source bound excludes the entire source allocation before copying.
    wrapped,loader=compile_m2(out/'loader',layout,adt,args,tag,linux,offset,len(data),len(rd))
    repeat,repeated=compile_m2(out/'repeat',layout,adt,args,tag,linux,offset,len(data),len(rd))
    if wrapped!=repeat or loader!=repeated:raise ValueError('loader not reproducible')
    payload,preserved=repack_v2(a,wrapped,tag,ramdisk=rd)
    from cryptography.hazmat.primitives import serialization
    key=serialization.load_pem_private_key(KEY.read_bytes(),None)
    image,avb=diagnostic_footer(payload,a,key)
    if token(tag,True) in image or (tag+'-D').encode() in image:raise ValueError('precomputed success marker')
    (out/'boot_a-xnu-m2.img').write_bytes(image)
    (out/'initramfs.cpio').write_bytes(rd)
    shutil.copyfile(kernel,out/'kernel.ums512hw.macho');shutil.copyfile(record,out/'kernel-audit.json')
    manifest=dict(schema=2,kind='xnu-arm-init-courier',tag=tag,bytes=len(image),sha256=hashlib.sha256(image).hexdigest(),
        kernel_sha256=report['sha256'],source_xnu=proof['source_commit'],symbols={k:hex(sym[k]) for k in required},
        arm_init_checkpoint_calls=[hex(x) for x in calls],layout=layout,loader=loader,
        ramdisk_bytes=len(rd),macho_offset=offset,avb=avb,preserved_components=preserved,
        capabilities=capabilities,reproducible_loader=True,hardware_tested=False,hardware_pass=False,
        entropy='diagnostic zeros, never used for OS security; mandatory return before PE initialization',
        proof_channel='arm_init creates suffix; cache-clean EL1 return; unchanged Linux + existing PID1 copy it into USB iSerial',
        expected_usb_serial='M1-'+tag+'-D',xnu_usb_driver=False,
        source_hashes={p:sha(ROOT/p) for p in ('shim/ums512/xnu_entry.S','shim/ums512/xnu_entry.c',
            'shim/ums512/xnu_loader.c','shim/ums512/xnu_loader.h','shim/ums512/handoff.S',
            'xnu/platform/ums512/ums512_progress.c','xnu/platform/ums512/ums512_progress_return.S','standalone/init.c')})
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    return manifest


def verify_m2(out):
    from m1_standalone import part,unpack_cpio
    from macho_kernel import audit
    from xnu_kernel_qemu import symbols
    from boot_a_probe import token
    from avb import footer,verify_hash
    out=Path(out);m=json.loads((out/'manifest.json').read_text())
    image=(out/'boot_a-xnu-m2.img').read_bytes()
    if m['kind']!='xnu-arm-init-courier' or len(image)!=67108864 or hashlib.sha256(image).hexdigest()!=m['sha256']:
        raise ValueError('M2 image identity mismatch')
    for path,digest in m['source_hashes'].items():
        if sha(ROOT/path)!=digest:raise ValueError('M2 source changed: '+path)
    rd=part(image,'ramdisk');members=unpack_cpio(rd)
    data=members['xnu.macho']['data'];r=audit(data,zero_slide_local_relocations=True)
    if r['sha256']!=m['kernel_sha256'] or data!=(out/'kernel.ums512hw.macho').read_bytes():raise ValueError('Mach-O identity')
    sym=symbols(data)
    if any(sym[k]!=int(v,0) for k,v in m['symbols'].items()):raise ValueError('XNU symbols changed')
    k=part(image,'kernel');loader=m['loader'];stub=loader['stub_offset']
    blob=(out/'loader/loader.bin').read_bytes()
    if k[stub:stub+len(blob)]!=blob or blob!=(out/'repeat/loader.bin').read_bytes():raise ValueError('loader bytes changed')
    original=part((ROOT/'out/backup-20261030-204557/boot_b.img').read_bytes(),'kernel')
    restored=bytearray(k[:len(original)]);restored[:4]=original[:4];restored[16:24]=original[16:24]
    if restored!=original:raise ValueError('courier Linux changed')
    if rd!=(out/'initramfs.cpio').read_bytes() or rd[m['macho_offset']:m['macho_offset']+len(data)]!=data:
        raise ValueError('ramdisk/Mach-O offset changed')
    if token(m['tag'],True) in image or (m['tag']+'-D').encode() in image:raise ValueError('success precomputed')
    v=footer(image)['vbmeta'];d=v['descriptors'][0]
    if v['flags'] or v['rollback_index']!=5 or not v['rsa_signature_matches_embedded_key'] or not verify_hash(d,image)['matches']:
        raise ValueError('AVB signature/hash/policy failed')
    return dict(status='M2_OFFLINE_IMAGE_VERIFIED',sha256=m['sha256'],kernel_sha256=r['sha256'],
                genuine_checkpoint_call=m['arm_init_checkpoint_calls'],hardware_pass=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['build','verify','m2-build','m2-verify']);p.add_argument('--out',type=Path,default=DEFAULT)
    p.add_argument('--kernel',type=Path);p.add_argument('--record',type=Path)
    a=p.parse_args()
    result=build_m2(a.kernel,a.record,a.out) if a.action=='m2-build' else verify_m2(a.out) if a.action=='m2-verify' else build(a.out) if a.action=='build' else verify(a.out)
    print(json.dumps(result,indent=2))
