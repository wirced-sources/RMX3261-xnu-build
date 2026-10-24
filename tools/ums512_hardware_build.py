"""Separate UMS512HW source/config/component path; no hardware-ready kernel.

Uses pinned genuine XNU and common native portability patches only. Full install
is deliberately unavailable: physical IRQ/entropy/RTC/storage are unqualified.
Never delegates physical execution to the QEMU drivers or publishes anything.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from build import ROOT, tool
from xnu_native import PATCHES, clone_work, full_master, master_for_validation, rewrite, specs, source as pinned_source
from xnu_build import FLAGS, PLATFORM, audit_object, facts, sha, upstream_abi
from xnu_config import configure, enforcement_probe
from xnu_host import unix

COMMON = (*PATCHES[:17], PATCHES[-1])
if [int(Path(p).name[:4]) for p in COMMON] != [*range(1,18),5] or any('qemu' in p for p in COMMON):
    raise ValueError('review hardware common-patch allowlist after native series changes')
QUALIFICATION_ERROR = 'UMS512HW: physical IRQ/delegation/backend not qualified; M1 NO-GO'


def hardware_master(original):
    text=full_master(original)
    if text.count('ums512 nos_arm_asm')!=1:raise ValueError('hardware feature insertion point changed')
    text=text.replace('ums512 nos_arm_asm','ums512 ums512_hardware nos_arm_asm')
    # OPTIONS/<source> becomes a config device/count header. Keep TARGET a
    # distinct ordinary option so SETUP/config retains its compiler -D flag.
    return text+'\noptions UMS512_HARDWARE_TARGET # <ums512_hardware>\noptions UMS512_HARDWARE_SOURCE # <ums512_hardware>\n'


def prepare(work, native=False):
    work=Path(work).resolve();work.relative_to((ROOT/'out').resolve())
    work.mkdir(parents=True,exist_ok=True)
    src=clone_work('xnu',work)
    for patch in COMMON:
        subprocess.run(['git','-C',src,'apply','--check',ROOT/patch],check=True,capture_output=True)
        subprocess.run(['git','-C',src,'apply',ROOT/patch],check=True,capture_output=True)
    definitions=src/'makedefs/MakeInc.def'
    rewrite(definitions,'VMAPPLE UMS512\n','VMAPPLE UMS512 UMS512HW\n')
    rewrite(definitions,'ifneq ($(CURRENT_MACHINE_CONFIG),UMS512)',
        'ifeq ($(filter UMS512 UMS512HW,$(CURRENT_MACHINE_CONFIG)),)')
    with definitions.open('a',newline='\n') as stream:
        stream.write('\nMACHINE_FLAGS_ARM64_UMS512HW = -DARM64_BOARD_CONFIG_UMS512 -DUMS512_HARDWARE_TARGET=1 -march=armv8.2-a\n')
    shutil.copyfile(PLATFORM/'UMS512.h',src/'pexpert/pexpert/arm64/UMS512.h')
    (src/'osfmk/ums512').mkdir()
    shutil.copyfile(PLATFORM/'cpu_entry.h',src/'osfmk/ums512/cpu_entry.h')
    (src/'iokit/ums512').mkdir()
    shutil.copyfile(PLATFORM/'UMS512HardwarePlatform.cpp',src/'iokit/ums512/UMS512HardwarePlatform.cpp')
    with (src/'iokit/conf/files').open('a',newline='\n') as stream:
        stream.write('\nOPTIONS/ums512_hardware_source optional ums512_hardware_source\n')
        stream.write('\niokit/ums512/UMS512HardwarePlatform.cpp optional ums512_hardware_source\n')
    catalogue=src/'iokit/KernelConfigTables.cpp'
    rewrite(catalogue,'    "("\n','    "("\n#if UMS512_HARDWARE_TARGET\n'
        '    " { \'IOClass\' = RMXUMS512Platform; \'IOProviderClass\' = IOPlatformExpertDevice;"\n'
        '    " \'IONameMatch\' = \'rmx3261,ums512\'; \'IOProbeScore\' = 1000:32; },"\n#endif\n')
    # Never let a target named UMS512HW fall through to the stock Group0 route.
    fiq=src/'pexpert/arm/pe_fiq.c'
    clocks=src/'pexpert/arm/pe_identify_machine.c'
    if native:
        # Real call sites, not success stubs. The native linker must diagnose
        # these missing physical implementations; do not borrow QEMU backends.
        shutil.copyfile(PLATFORM/'ums512_hw_backend.h',src/'pexpert/arm/ums512_hw_backend.h')
        rewrite(fiq,'#if HAS_GIC_V3',
            '#if UMS512_HARDWARE_TARGET\n#include "ums512_hw_backend.h"\n'
            'void pe_init_fiq(void) { ums512_hw_irq_initialize(); }\n#elif HAS_GIC_V3')
        rewrite(clocks,'pe_identify_machine(boot_args * bootArgs)\n{',
            'pe_identify_machine(boot_args * bootArgs)\n{\n#if UMS512_HARDWARE_TARGET\n'
            '\tums512_hw_clock_identify(bootArgs);\n#else')
        rewrite(clocks,'\n}\n\nvm_offset_t\npe_arm_get_soc_base_phys',
            '\n#endif /* UMS512_HARDWARE_TARGET */\n}\n\nvm_offset_t\npe_arm_get_soc_base_phys')
        clocks.write_text('#if UMS512_HARDWARE_TARGET\n#include "ums512_hw_backend.h"\n#endif\n'+clocks.read_text(),
            encoding='utf-8',newline='\n')
        # Platform computations and transfer use the real native build graph.
        target=src/'osfmk/ums512'
        for name in ('platform.c','platform.h','diag.c','abi.c','entry_regs.S'):
            dest={'platform.c':'ums512_platform.c','diag.c':'ums512_diag.c','abi.c':'ums512_abi.c',
                  'entry_regs.S':'ums512_entry_regs.s'}.get(name,name)
            shutil.copyfile(PLATFORM/name,target/dest)
        rewrite(target/'platform.h','../../../shim/ums512/xnu_boot.h','xnu_boot.h')
        shutil.copyfile(ROOT/'shim/ums512/xnu_boot.h',target/'xnu_boot.h')
        shutil.copyfile(ROOT/'shim/ums512/handoff.S',target/'ums512_handoff.s')
        facts(target)
        with (src/'osfmk/conf/files.arm64').open('a',newline='\n') as stream:
            stream.write('\nOPTIONS/ums512_hardware_source\toptional ums512_hardware_source\n')
            for name in ('ums512_platform.c','ums512_diag.c','ums512_abi.c','ums512_entry_regs.s','ums512_handoff.s'):
                stream.write(f'\nosfmk/ums512/{name}\toptional ums512_hardware_source\n')
        from xnu_crypto import install as install_crypto
        install_crypto(src)
    else:
        fiq.write_text(f'#if UMS512_HARDWARE_TARGET\n#error "{QUALIFICATION_ERROR}"\n#endif\n'+fiq.read_text(),
            encoding='utf-8',newline='\n')
        clocks.write_text('#if UMS512_HARDWARE_TARGET\n'
            '#error "UMS512HW: physical clock-info policy unqualified; legacy defaults are not observations"\n'
            '#endif\n'+clocks.read_text(),encoding='utf-8',newline='\n')
    original=(src/'config/MASTER.arm64.MacOSX').read_text()
    board=hardware_master(original)
    (src/'config/MASTER.arm64.ums512hw.MacOSX').write_text(board,encoding='ascii',newline='\n')
    master=(src/'config/MASTER').read_text()
    _,native=configure(master,master_for_validation(full_master(original)))
    conf,features=configure(master,master_for_validation(board))
    if set(features)-set(native)!={'ums512_hardware'} or set(native)-set(features):
        raise ValueError('hardware configuration changed native security features')
    report=dict(target='DEVELOPMENT ARM64 UMS512HW',source_commit=specs()[1]['xnu']['commit'],
        patches={p:sha(ROOT/p) for p in COMMON},features=features,
        qemu_drivers_included=False,security_features_preserved=True,
        full_kernel_linked=False,hardware_qualified=False,m1='NO-GO',
        blockers=['physical Group1NS/SRE/delegation and timer backend','observed entropy and RTC provider',
                  'live memory/cache/EL and recovery proof','physical storage and complete PE implementation'],
        compile_gate=QUALIFICATION_ERROR)
    report['native_link_attempt']=native
    if native:
        report['compile_gate']=None
        report['required_physical_implementations']=['ums512_hw_irq_initialize','ums512_hw_clock_identify']
    # Configuration generation uses actual SETUP/config, not header facades.
    host=ROOT/'out/m010/host';config_binary=host/'config'
    if os.name=='nt' and config_binary.exists():
        expected=json.loads((host/'results.json').read_text())['config_sha256']
        if sha(config_binary)!=expected: raise ValueError('SETUP/config binary changed')
        generated=work/'generated';generated.mkdir()
        config=generated/'config.DEVELOPMENT_ARM64_UMS512HW'
        config.write_text(conf+f'builddir "."\nobjectdir "{unix(generated)}"\nsourcedir "{unix(src)}"\n',
                          encoding='ascii',newline='\n')
        process=subprocess.run(['wsl','-d','Ubuntu','--exec',unix(config_binary),'-c',unix(src/'osfmk/conf'),unix(config)],
            capture_output=True,text=True,timeout=45)
        if process.returncode or process.stderr.strip(): raise RuntimeError('SETUP/config: '+process.stderr)
        makefile=(generated/'Makefile').read_text()
        if '-DUMS512_HARDWARE_TARGET' not in makefile: raise ValueError('hardware option not materialized')
        if native:
            for name in ('ums512_platform','ums512_diag','ums512_abi','ums512_entry_regs','ums512_handoff'):
                if name+'.o' not in makefile:raise ValueError('missing native hardware object '+name)
        report['enforcement_config']=enforcement_probe(makefile,(src/'bsd/kern/kern_cs.c').read_text(),[tool('clang','CLANG')])
        report['generated_headers']={p.name:sha(p) for p in generated.glob('*.h')}
        report['set_up_config']='PASS; actual OSFMK Makefile/header generation'
    else:
        report['set_up_config']='UNVERIFIED: local SETUP/config executable unavailable'
    report['qualification_compile_refusals']={}
    for name,message in (() if native else (('pe_fiq.c',QUALIFICATION_ERROR),('pe_identify_machine.c','physical clock-info policy unqualified'))):
        p=subprocess.run([tool('clang','CLANG'),'--target=arm64-apple-macos11','-E','-DUMS512_HARDWARE_TARGET=1',
            str(src/'pexpert/arm'/name)],capture_output=True,text=True,timeout=30)
        if not p.returncode or message not in p.stderr:raise ValueError('hardware qualification gate did not reject '+name)
        report['qualification_compile_refusals'][name]=dict(exit=p.returncode,expected_gate_reached=True)
    report['platform_sources']={name:sha(PLATFORM/name) for name in ('UMS512.h','cpu_entry.h','UMS512HardwarePlatform.cpp')}
    (work/'prepared.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    return report


def components(directory):
    directory=Path(directory).resolve();directory.relative_to((ROOT/'out').resolve())
    directory.mkdir(parents=True,exist_ok=True);facts(directory)
    # Reuse the independent component builder: same real C memory/CPU gates,
    # data ABI, snapshot and new PA-only transfer; no kernel entry observer.
    sources=[PLATFORM/p for p in ('platform.c','diag.c','entry_regs.S','abi.c')]
    sources += [ROOT/'shim/ums512/handoff.S',upstream_abi(directory)]
    src=pinned_source('xnu')
    result={}
    env=dict(os.environ,TMP=str(directory),TEMP=str(directory),TMPDIR=str(directory))
    for macho,target in ((False,'aarch64-none-elf'),(True,'arm64-apple-macos11')):
        for source in sources:
            name=source.stem+('.macho.o' if macho else '.elf.o');path=directory/name
            args=[tool('clang','CLANG'),'--target='+target,*FLAGS,'-DUMS512_HARDWARE_TARGET=1',
                '-I',str(directory),'-I',str(PLATFORM)]
            for inc in ('pexpert','osfmk','bsd'):args+=['-I',str(src/inc)]
            subprocess.run([*args,'-c',str(source),'-o',str(path)],env=env,check=True,capture_output=True,timeout=30)
            result[name]=dict(bytes=path.stat().st_size,sha256=sha(path),**audit_object(path,macho))
    return result


def pe_probe(work):
    """Genuine IOKit header dependency probe; no mock DriverKit/allocator headers."""
    work=Path(work);src=work/'xnu';generated=work/'generated'
    makefile=(generated/'Makefile').read_text()
    import shlex
    definitions=shlex.split(re.search(r'^export CONFIG_DEFINES = (.+)$',makefile,re.M)[1])
    args=[tool('clang','CLANG'),'--target=arm64-apple-macos11','-std=gnu++17','-ffreestanding',
        '-fno-exceptions','-fno-rtti','-fblocks','-DKERNEL=1','-DKERNEL_PRIVATE=1','-DPRIVATE=1',
        '-DXNU_KERNEL_PRIVATE=1','-DIOKIT_KERNEL_PRIVATE=1','-DARM64_BOARD_CONFIG_UMS512',*definitions,
        '-include',str(generated/'meta_features.h')]
    for inc in (generated,src/'bsd',src/'osfmk',src/'pexpert',src/'iokit',src/'libkern',
                src/'osfmk/libsa',src/'EXTERNAL_HEADERS',src):
        args+=['-I',str(inc)]
    # OSFMK-private MIG headers are NOT the installed IOKit export context.
    # Do not use them to make a direct-source probe appear like a native build.
    output=work/'UMS512HardwarePlatform.macho.o'
    p=subprocess.run([*args,'-c',str(src/'iokit/ums512/UMS512HardwarePlatform.cpp'),'-o',str(output)],
        capture_output=True,text=True,timeout=30)
    report=dict(exit=p.returncode,stderr=p.stderr,compiled=p.returncode==0,
        scope='Direct-source IOKit dependency probe; native exported SDK/MIG/IIG context not available',
        missing_prerequisites=['native installed Kernel.framework/exported MIG headers',
            'IIG-generated DriverKit/IOService.h (only .iig source is present)',
            'Apple Clang allocator builtins; no substitute definitions'])
    if p.returncode==0:report.update(sha256=sha(output),**audit_object(output,True))
    (work/'pe-probe.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,default=ROOT/'out/ums512-hardware')
    parser.add_argument('--prepare',action='store_true')
    parser.add_argument('--pe-probe',action='store_true')
    parser.add_argument('--native-prepare',action='store_true',help='full native graph with unresolved real hardware interfaces')
    a=parser.parse_args();a.work.resolve().relative_to((ROOT/'out').resolve())
    report=prepare(a.work,native=a.native_prepare) if a.prepare else dict(full_kernel_linked=False,m1='NO-GO')
    report['objects']=components(a.work/'objects');repeat=components(a.work/'repeat')
    if report['objects']!=repeat:raise ValueError('hardware component build not reproducible')
    report['reproducible']=True
    if a.pe_probe:report['pe_probe']=pe_probe(a.work)
    (a.work/'results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('UMS512HW: 12 component objects reproducible; full kernel BLOCKED, hardware UNVERIFIED; M1 NO-GO')
