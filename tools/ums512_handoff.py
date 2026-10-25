"""Offline FDT -> XNU8796 ADT/boot_args. No PA selection, loader or hardware approval."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from fdt import FDT
from extract_hardware import extract
from ums512_target import ROOT, extent, profile, ram_windows
from macho_kernel import audit, mapping, bootstrap_coverage

MODEL = b'rmx3261,ums512\0' # Port software identity, not an Apple/firmware identity.
PAGE = 16384
STATE_FIELDS = ('current_el','sctlr','midr','mpidr','mmfr0','mmfr1','ctr','cntfrq')
LAYOUT_FIELDS = ('window','virt_base','adt_pa','args_pa','top','stack','log','fdt_pa','live_exclusions')
CLAIMS = ('cache_clean_to_poc','instruction_fetch_coherent','dma_quiesced','secondary_cpus_quiesced')


def num(value):
    if isinstance(value, str): value = int(value,0)
    if type(value) is not int or not 0 <= value < 1 << 64: raise ValueError('expected uint64')
    return value


def region(value):
    return extent(dict(base=hex(num(value['base'])),size=hex(num(value['size']))))


def node(name, props=(), children=()):
    """Exact DeviceTreeNode/DeviceTreeNodeProperty wire layout, no placeholders."""
    if not name or len(name)>63 or '\0' in name or '/' in name:raise ValueError('invalid ADT entry name')
    props = [('name',name.encode('ascii')+b'\0'),*props]
    if len(set(k for k,v in props)) != len(props): raise ValueError('duplicate ADT property')
    out = bytearray(struct.pack('<II',len(props),len(children)))
    for key,value in props:
        key=key.encode('ascii')
        if not key or len(key)>31 or b'\0' in key or not isinstance(value,bytes) or len(value)>1024*1024:
            raise ValueError('invalid ADT property')
        out += struct.pack('<32sI',key,len(value))+value+b'\0'*(-len(value)%4)
    return bytes(out)+b''.join(children)


def inspect_fdt(data):
    if len(data)>1024*1024: raise ValueError('oversized FDT')
    tree=FDT(data);board=extract(data);p=profile(board)
    gic=next(n for n in tree.nodes.values() if 'arm,gic-v3' in n.strings('compatible'))
    if gic.props.get('interrupt-controller')!=b'':
        raise ValueError('missing/invalid GIC interrupt-controller property')
    handle=gic.cells('phandle',gic.cells('linux,phandle',[]))
    if len(handle)!=1 or handle[0] in (0,0xffffffff) or gic.cells('#interrupt-cells') != [3]:
        raise ValueError('missing three-cell GIC interrupt parent')
    for n in tree.nodes.values():
        if n is not gic and (n.cells('phandle',[])==handle or n.cells('linux,phandle',[])==handle):
            raise ValueError('duplicate GIC phandle')
    if 'linux,phandle' in gic.props and gic.cells('linux,phandle')!=handle:
        raise ValueError('conflicting GIC phandles')
    wanted=[gic,tree.nodes[board['stdout_node']]]
    wanted += [n for n in tree.nodes.values() if 'arm,armv8-timer' in n.strings('compatible') or
               ('sprd,sdhc-r11p1' in n.strings('compatible') and n.cells('bus-width')==[8])]
    required=wanted+[n for n in tree.nodes.values() if n.strings('device_type') in (['cpu'],['memory']) or
                     'arm,psci-0.2' in n.strings('compatible')]
    for n in required:
        current=n
        while current is not None:
            if current.strings('status') not in ([],['okay'],['ok']):
                raise ValueError('required FDT node or ancestor is unavailable')
            current=current.parent
    for n in wanted:
        if 'interrupts-extended' in n.props: raise ValueError('extended interrupts require separate binding review')
        current=n
        while current is not None and 'interrupt-parent' not in current.props: current=current.parent
        if current is None or current.cells('interrupt-parent')!=handle:
            raise ValueError('IRQ specifier belongs to another interrupt controller')
    return board,p


def capture_fdt(directory):
    """Read one already saved verified capture, never ADB or a device tool."""
    from rmx3261_analyze import analyze_capture
    from rmx3261_collect import private_path
    directory=private_path(directory)
    result=analyze_capture(directory)
    if result['mode']!='ADB_SERVER_SHELL_V2' or result['statuses'].get('fdt')!='OK':
        raise ValueError('successful strict FDT from a saved live-format capture required')
    manifest=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    row=next(r for r in manifest['results'] if r['id']=='fdt')
    data=(directory/row['stdout']['file']).read_bytes()
    if len(data)!=row['stdout']['bytes'] or hashlib.sha256(data).hexdigest()!=row['stdout']['sha256']:
        raise ValueError('capture FDT changed after integrity validation')
    if hashlib.sha256((directory/'manifest.json').read_bytes()).hexdigest()!=result['manifest_sha256']:
        raise ValueError('capture manifest changed after integrity validation')
    return data,dict(source='saved Android FDT with manifest/byte integrity verified',
        manifest_sha256=result['manifest_sha256'],device_attestation=False)


def inherited_initrd(data):
    """Address-only exclusion; never copy or export the inherited payload."""
    tree=FDT(data);chosen=tree.nodes['/chosen'];names=('linux,initrd-start','linux,initrd-end')
    if not any(k in chosen.props for k in names):return []
    if not all(k in chosen.props and len(chosen.props[k]) in (4,8) for k in names):
        raise ValueError('incomplete/invalid inherited initrd range')
    start,end=(int.from_bytes(chosen.props[k],'big') for k in names)
    if end<=start:raise ValueError('inverted inherited initrd range')
    ram=[(a,a+s) for n in tree.nodes.values() if n.strings('device_type')==['memory'] for a,s in tree.physical(n)]
    if not any(a<=start and end<=b for a,b in ram):
        raise ValueError('inherited initrd is outside a single declared RAM bank')
    return [dict(base=hex(start),size=hex(end-start))]


def cpu_gate(state, p):
    s={k:num(state[k]) for k in STATE_FIELDS}
    if s['current_el']!=4: raise ValueError('EL1 cold handoff required; EL2 normalization not verified')
    if s['sctlr']&0x1005: raise ValueError('MMU/D-cache/I-cache must be off at XNU entry')
    if s['sctlr']&(1<<25): raise ValueError('little-endian EL1 data accesses required before XNU boot_args loads')
    core=(s['midr']>>4)&0xfff;aff=s['mpidr']&0xff00ffffff
    cpus={int(c['affinity'],0):0xd05 if c['core']=='arm,cortex-a55' else 0xd0a for c in p['cpus']}
    if (s['midr']>>24)&255!=0x41 or cpus.get(aff)!=core: raise ValueError('MIDR/affinity differs from target')
    if (s['mmfr0']>>20)&15 not in (1,2) or not 2<=s['mmfr0']&15<=6:
        raise ValueError('16KiB granule/physical address range unsupported')
    if not 1<=(s['mmfr1']>>20)&15<=3 or s['ctr']&15!=4 or (s['ctr']>>16)&15!=4:
        raise ValueError('PAN/cache line policy unsupported')
    # Match the physical clock backend and rtclock_usec_divisor=Hz/1e6.
    if not 1000000<=s['cntfrq']<=0xffffffff: raise ValueError('CNTFRQ is not a supported observed frequency')
    if p['timer_dt_frequency_hz'] is not None and p['timer_dt_frequency_hz']!=s['cntfrq']:
        raise ValueError('timer clock-frequency disagrees with supplied CNTFRQ')
    return s,aff


def make_adt(p, memory, regions, frequency, affinity, seed):
    u32=lambda *v:struct.pack('<'+'I'*len(v),*v)
    u64=lambda *v:struct.pack('<'+'Q'*len(v),*v)
    # A derived ADT bus translation convention, not a claim of contiguous MMIO.
    base=int(p['gic']['distributor'],0);end=int(p['emmc']['base'],0)+int(p['emmc']['size'],0)
    device=lambda name,compatible,regs,irq:node(name,[('compatible',compatible+b'\0'),
        ('reg',u64(*regs)),('interrupts',u32(irq)),('interrupt-parent',u32(1))])
    # ADT interrupt cells are translated INTIDs, not the original FDT triples.
    gic=node('gic',[('compatible',b'arm,gic-v3\0'),('AAPL,phandle',u32(1)),
        ('interrupt-controller',b''),('#interrupt-cells',u32(1)),
        ('reg',u64(0,0x20000,int(p['gic']['redistributors'],0)-base,int(p['gic']['redistributor_bytes'],0))),
        ('redistributor-stride',u64(int(p['gic']['stride'],0))),
        ('ums512,maintenance-intid',u32(p['gic']['maintenance']['intid']))])
    cpus=[node('cpu'+str(i),[('device_type',b'cpu\0'),('compatible',c['core'].encode()+b'\0'),
          ('reg',u32(int(c['affinity'],0))),('state',b'running\0' if int(c['affinity'],0)==affinity else b'stopped\0'),
          ('timebase-frequency',u32(frequency))]) for i,c in enumerate(p['cpus'])]
    return node('device-tree',[('model',MODEL),('compatible',MODEL),('#address-cells',u32(2)),('#size-cells',u32(2))],[
        node('defaults'),node('chosen',[('dram-base',u64(memory[0])),('dram-size',u64(memory[1]-memory[0])),
            ('random-seed',seed)], [node('memory-map',[(k,u64(a,b-a)) for k,(a,b) in regions.items()])]),
        node('cpus',[('#address-cells',u32(1)),('#size-cells',u32(0))],cpus),
        node('arm-io',[('device_type',b'ums512\0'),('#address-cells',u32(2)),('#size-cells',u32(2)),
            ('ranges',u64(0,base,end-base))],[gic,
            device('uart1',b'sprd,sc9836-uart',(int(p['uart']['base'],0)-base,int(p['uart']['size'],0)),p['uart']['irq']['intid']),
            device('emmc',b'sprd,sdhc-r11p1',(int(p['emmc']['base'],0)-base,int(p['emmc']['size'],0)),p['emmc']['irq']['intid'])]),
        node('timer',[('compatible',b'arm,armv8-timer\0'),('ums512,virtual-intid',u32(p['timer']['virtual']['intid']))])])


def adapt(fdt_data=None, kernel_data=None, context=None, seed=None):
    context=context or {};s=context.get('state',{});layout=context.get('layout',{})
    missing=[k for k,v in (('FDT bytes',fdt_data),('audited Mach-O bytes',kernel_data),('entropy bytes',seed)) if v is None]
    missing += ['state.'+k for k in STATE_FIELDS if s.get(k) is None]
    missing += ['layout.'+k for k in LAYOUT_FIELDS if layout.get(k) is None]
    missing += ['claim.'+k for k in CLAIMS if context.get(k) is not True]
    missing += [k for k in ('linux_x0','linux_x1_x2_x3','command_line') if context.get(k) is None]
    report=dict(scope='Offline data-only handoff contract; caller observations/ownership are unverified claims',
        structural_blockers=missing,approved_for_hardware=False,m1='NO-GO',
        hardware_blockers=['Recovery/secure policy/diagnostic channel unverified.',
            'Live ownership, cache/DMA/EL evidence and entropy provenance require physical qualification.',
            'Clock/IRQ code requires qualified live clocks/timers/GIC; RTC/entropy/storage backends unavailable.',
            'Panic reservation and complete Platform Expert startup contract are unqualified.',
            'Kernel source/profile/authenticity and platform clock-domain mappings require qualification.'])
    if fdt_data is not None:
        board,p=inspect_fdt(fdt_data)
        report['fdt_sha256']=hashlib.sha256(fdt_data).hexdigest()
        history=json.loads((ROOT/'docs/m05-memory.json').read_text())['regions']
        report['reservation_evidence']=dict(current_fdt_header_entries=len(board['memreserve']),
            current_reserved_memory_nodes=len(board['reserved_memory']),
            current_reserved_memory_ranges=sum(len(n['reg']) for n in board['reserved_memory']),
            historical_stage_records=len(history),
            historical_fdt_header_records=sum(r['name']=='memreserve' for r in history),
            historical_reserved_memory_records=sum(r['name'].startswith('/reserved-memory/') for r in history),
            historical_conditional_file_records=sum(r['name'].startswith('loader-file-only') for r in history),
            simultaneous_allocations_proven=False)
    if missing: return report,None,None
    state,aff=cpu_gate(s,p)
    if type(seed) is not bytes or len(seed)!=64 or not any(seed): raise ValueError('64-byte seed required; no default entropy')
    kernel=audit(kernel_data,zero_slide_local_relocations=True)
    memory=region(layout['window']);base,end=memory
    va,adt_pa,args_pa,top,fdt_pa=(num(layout[k]) for k in ('virt_base','adt_pa','args_pa','top','fdt_pa'))
    if (base|end|va|top)&(PAGE-1) or va>>48!=0xffff: raise ValueError('unaligned/noncanonical memory window')
    if fdt_pa%8 or not any(a<=fdt_pa and fdt_pa+len(fdt_data)<=b for a,b in map(extent,board['ram'])):
        raise ValueError('Linux x0 FDT PA is unaligned or outside RAM')
    if context.get('linux_x0') is None or num(context['linux_x0'])!=fdt_pa or context.get('linux_x1_x2_x3')!=[0,0,0]:
        raise ValueError('Linux input handoff does not identify the supplied FDT')
    # Deny every supplied live object and both historical and current carveouts.
    extra=[dict(base=hex(a),size=hex(b-a)) for a,b in map(region,layout['live_exclusions'])]
    baseline=json.loads((ROOT/'boards/ums512-hardware.json').read_text())
    extra += history+profile(baseline)['reserved']+inherited_initrd(fdt_data)
    extra += [dict(base=hex(fdt_pa),size=hex(len(fdt_data)))]
    allowed=[extent(r) for r in ram_windows(board,extra)]
    if not any(a<=base and end<=b for a,b in allowed): raise ValueError('managed RAM intersects reserved/live memory')
    live=[(base+s['vmaddr']-va,base+s['vmaddr']-va+s['vmsize']) for s in kernel['segments'] if s['initprot'] and s['vmsize']]
    stack,log=region(layout['stack']),region(layout['log'])
    if stack[0]%16 or stack[1]%16 or stack[1]-stack[0]<PAGE or log[0]%8 or log[1]-log[0]<272:
        raise ValueError('invalid stack/diagnostic extent')
    regions={'Kernel':(min(a for a,b in live),max(b for a,b in live)),
        'DeviceTree':(adt_pa,adt_pa+1),'BootArgs':(args_pa,args_pa+736),'BootStack':stack,'BootDiag':log}
    adt=make_adt(p,memory,regions,state['cntfrq'],aff,seed)
    regions['DeviceTree']=(adt_pa,adt_pa+len(adt))
    adt=make_adt(p,memory,regions,state['cntfrq'],aff,seed)
    ranges=sorted(regions.values())
    if any(a<base or b>top or b<=a for a,b in ranges) or any(a[1]>b[0] for a,b in zip(ranges,ranges[1:])):
        raise ValueError('handoff data overlap/outside explicit owned window')
    plan=mapping(kernel,base,va,end-base,adt_pa,len(adt),args_pa,top)
    header_pa=min(a for a,b in live)
    coverage=bootstrap_coverage(base,va,end-base,header_pa,[(a,b-a) for a,b in ranges],(base,end-base))
    command=context.get('command_line')
    if not isinstance(command,str) or not command.isascii() or '\0' in command or len(command.encode())>=608:
        raise ValueError('bounded explicit ASCII command line required')
    if '-noprogress' not in command.split(): raise ValueError('headless profile requires -noprogress; framebuffer is unknown')
    words=command.split()
    if len(words)!=len(set(words)) or set(words)-{'-noprogress','cpus=1'}:
        raise ValueError('unreviewed boot option for headless UP hardware contract')
    args=bytearray(736);struct.pack_into('<HH4x4Q',args,0,2,2,va,base,end-base,top)
    struct.pack_into('<QI',args,96,plan['deviceTreeP'],len(adt))
    args[108:108+len(command)]=command.encode();struct.pack_into('<Q',args,728,end-base)
    report.update(structural_pass=True,kernel_sha256=kernel['sha256'],image_va_slide=0,
        entry_pa=hex(plan['entry_pa']),branch_x0_physical_boot_args=hex(args_pa),
        boot_args_deviceTreeP_kva=hex(plan['deviceTreeP']),adt_bytes=len(adt),boot_args_bytes=len(args),
        supplied_cntfrq=state['cntfrq'],bootstrap_coverage=coverage,
        framebuffer='unknown; no video properties or fabricated scanout',entropy='supplied; quality/provenance unverified',
        unknown=['secure policy','GIC delegation/SRE','UART clocks/pins','RTC','storage','physical recovery'])
    return report,adt,bytes(args)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    inp=p.add_mutually_exclusive_group()
    inp.add_argument('--fdt',type=Path)
    inp.add_argument('--fdt-capture',type=Path,help='existing private diagnostic capture; offline manifest/hash validation only')
    for name in ('kernel','context','seed'):p.add_argument('--'+name,type=Path)
    p.add_argument('--out',type=Path,default=ROOT/'out/ums512-handoff')
    p.add_argument('--emit-data-only',action='store_true',help='ignored workspace data only, never a boot image')
    a=p.parse_args();a.out.resolve().relative_to((ROOT/'out').resolve())
    if any((a.out/name).exists() for name in ('device-tree.adt','boot_args.bin')):
        raise ValueError('existing handoff data retained; choose a fresh output directory')
    data,provenance=capture_fdt(a.fdt_capture) if a.fdt_capture else (a.fdt.read_bytes() if a.fdt else None,None)
    report,adt,args=adapt(data,a.kernel.read_bytes() if a.kernel else None,
        json.loads(a.context.read_text()) if a.context else None,a.seed.read_bytes() if a.seed else None)
    if provenance is not None:report['fdt_acquisition']=provenance
    a.out.mkdir(parents=True,exist_ok=True)
    (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    if a.emit_data_only and adt is not None:
        for name,data in (('device-tree.adt',adt),('boot_args.bin',args)):
            with (a.out/name).open('xb') as stream:stream.write(data)
    print('Offline handoff '+('structurally encoded' if adt else 'blocked by unknown inputs')+'; M1 NO-GO')
