"""Offline physical-XNU components. Never emits a flashable boot image or calls ADB.

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


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['build','verify']);p.add_argument('--out',type=Path,default=DEFAULT)
    a=p.parse_args()
    print(json.dumps(build(a.out) if a.action=='build' else verify(a.out),indent=2))
