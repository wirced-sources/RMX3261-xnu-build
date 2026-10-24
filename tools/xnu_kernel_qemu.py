"""Bounded execution of a natively built, audited XNU on QEMU virt only.

No observer, replacement arm_init, debugger memory writes, physical phone or
binary export. A debugger stop at arm_init is not execution: instructions must
actually be single-stepped. Later stops report reached boundaries separately.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time
import xml.etree.ElementTree as ET

from fdt import FDT
from macho_kernel import audit, mapping, bootstrap_coverage


def align(n, a=0x4000):
    return (n + a - 1) & -a


def virtual_timer_binding(tree):
    """Validate the actual QEMU timer's interrupt-parent/specifier before boot."""
    timers=[n for n in tree.nodes.values() if 'arm,armv8-timer' in n.strings('compatible')]
    gics=[n for n in tree.nodes.values() if 'arm,gic-v3' in n.strings('compatible')]
    if len(timers)!=1 or len(gics)!=1 or gics[0].cells('#interrupt-cells')!=[3]:
        raise ValueError('QEMU architectural timer/GIC binding unavailable')
    handle=gics[0].cells('phandle',[])
    if len(handle)!=1 or handle[0] in (0,0xffffffff):
        raise ValueError('QEMU GIC interrupt phandle unavailable')
    current=timers[0]
    while current is not None and 'interrupt-parent' not in current.props:
        current=current.parent
    if current is None or current.cells('interrupt-parent')!=handle:
        raise ValueError('QEMU timer interrupt parent differs from GIC')
    spec=timers[0].cells('interrupts',[])
    # arm,armv8-timer binding: secure physical, nonsecure physical, virtual,
    # hypervisor physical, optional hypervisor virtual. PPI numbers start at16.
    if len(spec)<12 or len(spec)%3 or spec[6:9]!=[1,11,4]:
        raise ValueError('QEMU virtual timer is not level-high PPI27')
    return {'intid':27,'trigger':'level-high','source':'QEMU arm,armv8-timer FDT, virtual specifier'}


def control_registers(registers, boot_args=False):
    """Do not publish arbitrary GPR leftovers from cryptographic functions."""
    fields = ('pc','lr','sp','cpsr') + (('x0',) if boot_args else ())
    return {name:registers[name] for name in fields if name in registers}


def plain_panic_arguments(block):
    # Pointer then promoted32-bit source line in an eight-byte vararg slot.
    # The upper four padding bytes are not an argument value.
    return struct.unpack_from('<QI',block)


def interrupt_mask_panic_arguments(block):
    """Exact pinned Darwin varargs ABI; omit the dynamic extra-info pointer."""
    if len(block) != 64:
        raise ValueError('interrupt-mask panic argument size mismatch')
    reason,elapsed,start,now,timeout,_,source=struct.unpack_from('<7Q',block)
    line=struct.unpack_from('<I',block,56)[0]
    return reason,elapsed,start,now,timeout,source,line


def init_process_panic_arguments(block):
    """Darwin variadic pointer/u32/pointer/u32; padding is never exported."""
    if len(block)!=32:
        raise ValueError('first-process panic argument size mismatch')
    path=struct.unpack_from('<Q',block)[0]
    error=struct.unpack_from('<I',block,8)[0]
    source,line=struct.unpack_from('<QI',block,16)
    return path,error,source,line


def image_cstring(data, segments, pointer, limit=512):
    """Only public audited-image strings, never arbitrary target memory."""
    owner = next((s for s in segments if s['vmaddr'] <= pointer < s['vmaddr']+s['filesize']),None)
    if owner:
        begin = owner['fileoff']+pointer-owner['vmaddr']
        end = min(begin+limit,owner['fileoff']+owner['filesize'])
        terminator = data.find(b'\0',begin,end)
        if terminator > begin:
            text = data[begin:terminator]
            if all(c in (9,10,13) or 32 <= c < 127 for c in text):
                return text.decode('ascii')
    return None


def symbols(data):
    at = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 2:
            so, count, strings, length = struct.unpack_from('<4I', data, at + 8)
            result = {}
            for i in range(count):
                name, typ, sect, desc, value = struct.unpack_from('<IBBHQ', data, so + 16*i)
                if typ & 0xe0 == 0 and typ & 0xe == 0xe:
                    start = strings+name
                    end = data.find(b'\0', start, strings+length)
                    if name >= length or end < 0:
                        raise ValueError('invalid kernel symbol string')
                    text = data[start:end].decode('ascii')
                    result[text] = value
            return result
        at += size
    raise ValueError('symbol table missing')


def node(name, props=(), children=()):
    props = [('name', name.encode() + b'\0'), *props]
    data = bytearray(struct.pack('<II', len(props), len(children)))
    for key, value in props:
        encoded = key.encode()
        if len(encoded) >= 32 or not value:
            raise ValueError('invalid ADT property')
        data += struct.pack('<32sI', encoded, len(value)) + value
        data += b'\0' * (-len(value) % 4)
    for child in children:
        data += child
    return data


def wrapper(args, entry, freq):
    # Only same-section local expressions: the extracted Mach-O text must have
    # zero relocations. Linux Image header offsets are relative to its start.
    def literal(reg, value):
        return '\n'.join(f'{"movz" if i == 0 else "movk"} {reg}, #{(value >> (16*i)) & 65535}, lsl #{16*i}' for i in range(4))
    return '''.section __TEXT,__text,regular,pure_instructions
Lhead:
 b Lentry
 .long 0
 .quad 0
 .quad Lend-Lhead
 .quad 8
 .quad 0,0,0
 .ascii "ARMd"
 .long 0
Lentry:
 msr DAIFSet, #15
 mrs x9, CurrentEL
 cmp x9, #4
 b.eq Lel1
 cmp x9, #8
 b.ne Lpark
 mrs x10, SCTLR_EL2
 tst x10, #1
 b.ne Lpark
 tst x10, #4
 b.ne Lpark
 mov x10, #(1 << 31)
 msr HCR_EL2, x10
 mov x10, #0x33ff
 msr CPTR_EL2, x10
 mov x10, #3
 msr CNTHCTL_EL2, x10
 msr CNTVOFF_EL2, xzr
 adr x10, Lel1
 msr ELR_EL2, x10
 mov x10, #0x3c5
 msr SPSR_EL2, x10
 isb
 eret
Lel1:
''' + literal('x11', freq) + '''
 mrs x10, CNTFRQ_EL0
 str w10, [x11]
''' + literal('x0', args) + '\n' + literal('x16', entry) + '''
 mov x1, xzr
 mov x2, xzr
 mov x3, xzr
 br x16
Lpark:
 wfe
 b Lpark
Lend:
'''


def extract_wrapper(data):
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise ValueError('adapter must be plain ARM64 Mach-O object')
    at, sections = 32, []
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x19:
            for i in range(struct.unpack_from('<I', data, at+64)[0]):
                pos = at+72+80*i
                name = data[pos:pos+16].rstrip(b'\0')
                addr, length, offset, alignment, roff, nreloc = struct.unpack_from('<QQ4I', data, pos+32)
                if nreloc:
                    raise ValueError('adapter contains unresolved relocations')
                if name == b'__text':
                    sections.append(data[offset:offset+length])
        at += size
    if len(sections) != 1 or sections[0][56:60] != b'ARMd':
        raise ValueError('invalid adapter section/header')
    return sections[0]


class RSP:
    def __init__(self, conn):
        self.conn = conn

    def receive(self):
        while True:
            first = self.conn.recv(1)
            if not first:
                raise RuntimeError('debugger disconnected')
            if first == b'$':
                break
        data = bytearray()
        while (c := self.conn.recv(1)) != b'#':
            if not c or len(data) > 1024*1024:
                raise RuntimeError('invalid debugger packet')
            data += c
        checksum = b''
        while len(checksum) < 2:
            part = self.conn.recv(2-len(checksum))
            if not part:
                raise RuntimeError('debugger disconnected during checksum')
            checksum += part
        if checksum != f'{sum(data) & 255:02x}'.encode():
            raise ValueError('debugger packet checksum mismatch')
        self.conn.sendall(b'+')
        return data.decode('ascii')

    def command(self, text):
        data = text.encode('ascii')
        self.conn.sendall(b'$' + data + b'#' + f'{sum(data) & 255:02x}'.encode())
        result = self.receive()
        if result.startswith('E'):
            raise RuntimeError('debugger rejected command: ' + text.split(',')[0])
        return result

    def registers(self):
        data = bytes.fromhex(self.command('g'))
        if len(data) < 33*8:
            raise ValueError('short AArch64 register set')
        indices = [(f'x{i}',i) for i in range(7)] + [('x12',12),('x16',16),('lr',30),('sp',31),('pc',32)]
        result = {name: hex(struct.unpack_from('<Q', data, i*8)[0]) for name,i in indices}
        if len(data) >= 268:
            result['cpsr'] = hex(struct.unpack_from('<I',data,264)[0])
        return result

    def system_registers(self):
        """Read advertised register numbers, never assume a QEMU register ABI."""
        self.command('qSupported:qXfer:features:read+')
        pending, seen, regs, nextnum = ['target.xml'], set(), {}, 0
        while pending:
            name = pending.pop(0)
            if name in seen:
                continue
            seen.add(name)
            xml, offset = '', 0
            while True:
                packet = self.command(f'qXfer:features:read:{name}:{offset:x},1000')
                if not packet or packet[0] not in 'ml':
                    raise ValueError('QEMU target XML unavailable')
                xml += packet[1:]
                offset += len(packet)-1
                if offset > 256*1024:
                    raise ValueError('QEMU target XML exceeds bound')
                if packet[0] == 'l':
                    break
            # QEMU9.2 target.xml uses xi:include without a namespace declaration.
            root = ET.fromstring(xml.replace('xi:include','include'))
            for child in root.iter():
                if child.tag.endswith('include'):
                    pending.append(child.attrib['href'])
                elif child.tag == 'reg':
                    number = int(child.attrib.get('regnum',nextnum))
                    nextnum = number+1
                    key = child.attrib['name'].upper()
                    if key in ('TTBR0_EL1','TTBR1_EL1','TCR_EL1','SCTLR_EL1','MAIR_EL1'):
                        value = bytes.fromhex(self.command(f'p{number:x}'))
                        if len(value) != 8:
                            raise ValueError('short QEMU system register')
                        regs[key] = hex(int.from_bytes(value,'little'))
        return regs


def virtual_uart_binding(tree):
    """Only allow facts from QEMU's actual PL011 and its fixed uartclk."""
    nodes=[n for n in tree.nodes.values() if 'arm,pl011' in n.strings('compatible')]
    if len(nodes)!=1:
        raise ValueError('expected exactly one QEMU PL011')
    uart=nodes[0]
    chosen=tree.nodes.get('/chosen')
    if chosen is None or chosen.strings('stdout-path')!=[uart.path]:
        raise ValueError('QEMU stdout is not the PL011')
    names=uart.strings('clock-names'); clocks=uart.cells('clocks',[])
    if names!=['uartclk','apb_pclk'] or len(clocks)!=2:
        raise ValueError('unsupported QEMU UART clocks')
    providers=[n for n in tree.nodes.values() if n.cells('phandle',[])==[clocks[0]]]
    if len(providers)!=1 or 'fixed-clock' not in providers[0].strings('compatible') or providers[0].cells('#clock-cells')!=[0]:
        raise ValueError('QEMU UART fixed-clock provider not found')
    if clocks[0]!=clocks[1]:
        raise ValueError('QEMU UART clocks do not share the fixed clock')
    frequency=providers[0].cells('clock-frequency',[])
    regs=tree.reg(uart)
    if len(frequency)!=1 or not 2000000<=frequency[0]<=200000000 or len(regs)!=1 or not 0x1000<=regs[0][1]<=0x10000:
        raise ValueError('invalid QEMU UART clock/range')
    return {'physical':regs[0][0],'bytes':regs[0][1],'clock_hz':frequency[0],
            'source':'QEMU arm,pl011 FDT and fixed uartclk'}


def virtual_rtc_binding(tree):
    nodes=[n for n in tree.nodes.values() if 'arm,pl031' in n.strings('compatible')]
    if len(nodes)!=1:
        raise ValueError('expected exactly one QEMU PL031 RTC')
    regs=tree.reg(nodes[0])
    if len(regs)!=1 or not 0x1000<=regs[0][1]<=0x10000 or regs[0][0]&0xfff:
        raise ValueError('invalid QEMU RTC range')
    return {'physical':regs[0][0],'bytes':regs[0][1],'source':'QEMU arm,pl031 FDT'}


def inspect_mapping(rsp, address, system):
    """Read-only 16KB/full-L1 EL1 table walk for this exact QEMU profile."""
    tcr = int(system['TCR_EL1'],16)
    high = address >> 63
    granule = (tcr >> (30 if high else 14)) & 3
    size = (tcr >> (16 if high else 0)) & 63
    if granule != (1 if high else 2) or size != 17:
        return {'scope':'unsupported address/TCR for this bounded table walker'}
    table = int(system['TTBR1_EL1' if high else 'TTBR0_EL1'],16) & 0x0000ffffffffc000
    result = {'va':hex(address),'descriptors':[]}
    if rsp.command('Qqemu.PhyMemMode:1') != 'OK':
        raise RuntimeError('QEMU physical read mode unavailable')
    try:
        for level,shift in ((1,36),(2,25),(3,14)):
            entry = table+8*((address >> shift) & 2047)
            raw = bytes.fromhex(rsp.command(f'm{entry:x},8'))
            value = int.from_bytes(raw,'little')
            result['descriptors'].append({'level':level,'pa':hex(entry),'value':hex(value)})
            if not value & 1:
                result['valid'] = False
                break
            if level == 3 or value & 3 == 1:
                result.update(valid=True,pa=hex((value & 0x0000ffffffffc000 & -(1<<shift)) | (address & ((1<<shift)-1))),
                    access_flag=bool(value & (1<<10)),read_only=bool(value & (1<<7)),
                    privileged_execute_never=bool(value & (1<<53)))
                break
            table = value & 0x0000ffffffffc000
    finally:
        if rsp.command('Qqemu.PhyMemMode:0') != 'OK':
            raise RuntimeError('QEMU virtual read mode not restored')
    return result


def inspect_crypto(rsp, sym, result):
    """Only callback addresses/flags, never RNG contexts, seeds or output."""
    record = {}
    for name,size in (('_g_crypto_funcs',8),('_crypto_init',1)):
        if name in sym:
            value = int.from_bytes(bytes.fromhex(rsp.command(f'm{sym[name]:x},{size:x}')),'little')
            record[name] = {'address':hex(sym[name]),'value':hex(value)}
    pointer = int(record.get('_g_crypto_funcs',{}).get('value','0'),16)
    if pointer:
        # Pinned register_crypto.h:13 digest/HMAC pointers, then2 ECB pointers.
        # Only public mode descriptors/callback addresses, never key schedules.
        words=bytes.fromhex(rsp.command(f'm{pointer+15*8:x},10'))
        modes={}
        for name,address in zip(('encrypt','decrypt'),struct.unpack('<2Q',words)):
            mode={'address':hex(address)}
            if address:
                size,block,init,update=struct.unpack('<4Q',bytes.fromhex(rsp.command(f'm{address:x},20')))
                mode.update(context_bytes=size,block_bytes=block,init=hex(init),update=hex(update))
            modes[name]=mode
        record['aes_cbc_modes']=modes
        # register_crypto.h: four Random callbacks after40 preceding pointers.
        words = bytes.fromhex(rsp.command(f'm{pointer+40*8:x},20'))
        record['random_callbacks'] = [hex(v) for v in struct.unpack('<4Q',words)]
    try:
        record['system_registers'] = rsp.system_registers()
        if '_g_crypto_funcs' in sym:
            record['table_pointer_mapping'] = inspect_mapping(rsp,sym['_g_crypto_funcs'],record['system_registers'])
        if pointer:
            record['table_mapping']=inspect_mapping(rsp,pointer,record['system_registers'])
            for mode in record.get('aes_cbc_modes',{}).values():
                if int(mode['address'],16):
                    mode['mapping']=inspect_mapping(rsp,int(mode['address'],16),record['system_registers'])
    except (ValueError,RuntimeError,KeyError,ET.ParseError) as error:
        record['mapping_inspection_error'] = str(error)
    result.setdefault('crypto_registration_observations',[]).append(record)


def virtual_cpu_binding(tree):
    """This native profile is UP; validate actual QEMU FDT before making ADT."""
    cpus=[n for n in tree.nodes.values() if n.props.get('device_type')==b'cpu\0']
    if len(cpus)!=1:
        raise ValueError('QEMU native UP profile requires exactly one CPU')
    cpu=cpus[0]
    if (cpu.props.get('status',b'okay\0') not in (b'okay\0',b'ok\0') or
        tree.reg(cpu)!=[(0,0)]):
        raise ValueError('QEMU bootstrap CPU must be enabled with affinity zero')
    return dict(count=1,physical_id=0,path=cpu.path)


def execute(kernel, record, out, qemu, clang):
    data = kernel.read_bytes()
    report = audit(data, zero_slide_local_relocations=True)
    proof = json.loads(record.read_text())
    if (not proof.get('kernel_linked') or proof.get('sha256') != report['sha256']
            or proof.get('source_commit') != '1b191cb58250d0705d8a51287127505aa4bc0789'
            or proof.get('diagnostic_observer_included') is not False):
        raise ValueError('fresh genuine native-build provenance is required')
    sym = symbols(data)
    for name in ('_arm_init', '_arm_vm_init', '_kernel_bootstrap', '_panic'):
        if name not in sym:
            raise ValueError('genuine kernel symbol missing: ' + name)
    out.mkdir(parents=True, exist_ok=False)
    machine = 'virt,gic-version=3,virtualization=on'
    base_cmd = [qemu, '-machine', machine, '-cpu', 'cortex-a55', '-smp', '1', '-m', '512M', '-nic', 'none']
    fdt_path = out/'qemu.dtb'
    subprocess.run([*base_cmd, '-machine', machine+',dumpdtb='+str(fdt_path), '-display','none'], check=True, capture_output=True, timeout=20)
    tree = FDT(fdt_path.read_bytes())
    cpu_binding=virtual_cpu_binding(tree)
    timer_binding=virtual_timer_binding(tree)
    memory = [tree.reg(n) for n in tree.nodes.values() if n.props.get('device_type') == b'memory\0']
    gics = [tree.reg(n) for n in tree.nodes.values() if 'arm,gic-v3' in n.strings('compatible')]
    if memory != [[(0x40000000, 0x20000000)]] or len(gics) != 1 or len(gics[0]) != 2:
        raise ValueError('unexpected QEMU virt RAM/GIC layout')
    pa, mem = memory[0][0]
    gicd, gicr = gics[0]
    uart=virtual_uart_binding(tree) if '_ums512_uart_proof' in sym else None
    rtc=virtual_rtc_binding(tree) if '_ums512_platform_proof' in sym else None
    devices_end=gicr[0]+gicr[1]
    if uart:
        if uart['physical']<devices_end or uart['physical']+uart['bytes']>pa:
            raise ValueError('QEMU UART overlaps GIC/RAM')
        devices_end=max(devices_end,uart['physical']+uart['bytes'])
    if rtc:
        if rtc['physical']<devices_end or rtc['physical']+rtc['bytes']>pa:
            raise ValueError('QEMU RTC overlaps GIC/UART/RAM')
        devices_end=max(devices_end,rtc['physical']+rtc['bytes'])
    va = min(s['vmaddr'] for s in report['segments'] if s['initprot'] and s['vmsize']) & -0x2000000
    end = max(s['vmaddr']+s['vmsize'] for s in report['segments'] if s['initprot'])
    adt_pa = align(pa+end-va)
    adt = node('device-tree', [('model',b'qemu,virt\0')], [
        node('defaults'), # pmap requires the node; absent ASID property uses its real default.
        node('chosen', [('dram-base',struct.pack('<Q',pa)),('dram-size',struct.pack('<Q',mem)),('random-seed',os.urandom(64))], [node('memory-map')]),
        node('cpus', children=[node('cpu0',[('device_type',b'cpu\0'),('state',b'running\0'),('reg',struct.pack('<I',cpu_binding['physical_id'])),('timebase-frequency',struct.pack('<I',0))])]),
        node('arm-io',[('device_type',b'qemu,virt\0'),('ranges',struct.pack('<3Q',0,gicd[0],devices_end-gicd[0]))],
            [node('gic',[('reg',struct.pack('<4Q',0,gicd[1],gicr[0]-gicd[0],gicr[1]))])]+
            ([node('uart0',[('compatible',b'arm,pl011\0'),('reg',struct.pack('<2Q',uart['physical']-gicd[0],uart['bytes'])),
                            ('clock-frequency',struct.pack('<I',uart['clock_hz']))])] if uart else [])+
            ([node('rtc',[('compatible',b'arm,pl031\0'),('reg',struct.pack('<2Q',rtc['physical']-gicd[0],rtc['bytes']))])] if rtc else []))])
    args_pa = align(adt_pa+len(adt))
    top = args_pa+0x4000
    plan = mapping(report,pa,va,mem,adt_pa,len(adt),args_pa,top)
    header_pa = pa+min(s['vmaddr'] for s in report['segments'] if s['initprot'] and s['vmsize'])-va
    bootstrap_coverage(pa,va,mem,header_pa,[(header_pa,top-header_pa)],(pa,mem))
    raw = bytearray(top-header_pa)
    for s in report['segments']:
        if s['initprot']:
            off = pa+s['vmaddr']-va-header_pa
            raw[off:off+s['filesize']] = data[s['fileoff']:s['fileoff']+s['filesize']]
    raw[adt_pa-header_pa:adt_pa-header_pa+len(adt)] = adt
    args = bytearray(736)
    struct.pack_into('<HH',args,0,2,2)
    struct.pack_into('<4Q',args,8,va,pa,mem,top)
    struct.pack_into('<Q',args,96,plan['deviceTreeP'])
    struct.pack_into('<I',args,104,len(adt))
    # Original MacOSX progress UI requires a framebuffer. This QEMU profile is
    # headless: use its genuine UI-only boot argument, not fabricated video RAM.
    command_line = b'-noprogress'
    if uart:
        command_line += b' serial=1'
    runtime_requested = '_ums512_runtime_proof' in sym
    if runtime_requested:
        command_line += b' ums512-selftest=1'
    args[108:108+len(command_line)] = command_line
    struct.pack_into('<Q',args,728,mem)
    raw[args_pa-header_pa:args_pa-header_pa+len(args)] = args
    (out/'kernel.physical.bin').write_bytes(raw)
    freq = adt_pa+adt.index(b'timebase-frequency\0')+36
    source, obj, image = out/'entry.s',out/'entry.o',out/'entry.Image'
    source.write_text(wrapper(args_pa,plan['entry_pa'],freq))
    subprocess.run([clang,'-target','arm64-apple-macos11','-c',str(source),'-o',str(obj)], check=True, timeout=30)
    image.write_bytes(extract_wrapper(obj.read_bytes()))
    if header_pa < pa+0x200000:
        raise ValueError('kernel overlaps QEMU Linux entry placement window')
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0))
        port = reserve.getsockname()[1]
    log = (out/'qemu.log').open('wb')
    proc = subprocess.Popen([*base_cmd,'-display','none','-serial',('file:'+str(out/'serial.log')) if uart else 'none','-monitor','none','-no-reboot','-S',
        '-gdb',f'tcp:127.0.0.1:{port}','-kernel',str(image),'-device',f'loader,file={out / "kernel.physical.bin"},addr={header_pa:#x},force-raw=on'],stdout=log,stderr=log)
    result = {'kernel_sha256':report['sha256'],'arm_init_executed':False,
              'kernel_boot_completed':False,'hardware_verified':False,'stops':[],
              'observation_window_seconds':180 if '_ums512_lab_exec_proof' in sym else (90 if '_ums512_storage_proof' in sym else 45),'boundary_limit':256,
              'boot_arguments':command_line.decode('ascii'),
              'virtual_timer_fdt_binding':timer_binding,'virtual_cpu_fdt_binding':cpu_binding,
              'virtual_uart_fdt_binding':uart,
              'virtual_rtc_fdt_binding':rtc,
              'kernel_runtime_tests_requested':runtime_requested,
              'returned_init_functions':[]}
    try:
        deadline = time.monotonic()+10
        while True:
            try:
                conn = socket.create_connection(('127.0.0.1',port),timeout=1)
                break
            except OSError:
                if time.monotonic()>deadline or proc.poll() is not None:
                    raise RuntimeError('QEMU debugger unavailable')
                time.sleep(0.05)
        with conn:
            conn.settimeout(15)
            rsp = RSP(conn)
            rsp.command('?')
            if rsp.command(f'Z1,{sym["_arm_init"]:x},4') != 'OK':
                raise RuntimeError('QEMU hardware breakpoint unavailable')
            try:
                rsp.command('c')
            except socket.timeout:
                conn.sendall(b'\x03')
                rsp.receive()
                result['stops'].append({'boundary':'timeout before arm_init',**control_registers(rsp.registers())})
                raise RuntimeError('bounded run stopped before genuine arm_init; inspect recorded PC/SP/x0')
            before = rsp.registers()
            result['arm_init_entry'] = control_registers(before,boot_args=True)
            if int(before['pc'],16) != sym['_arm_init']:
                raise ValueError('kernel stopped before genuine arm_init')
            if int(before['x0'],16) != va+args_pa-pa or int(before['sp'],16) % 16:
                raise ValueError('incorrect boot_args KVA or stack alignment at arm_init')
            owner = next(s for s in report['segments'] if s['vmaddr'] <= sym['_arm_init'] < s['vmaddr']+s['filesize'])
            offset = owner['fileoff']+sym['_arm_init']-owner['vmaddr']
            if bytes.fromhex(rsp.command(f'm{sym["_arm_init"]:x},20')) != data[offset:offset+32]:
                raise ValueError('executing arm_init bytes differ from audited native kernel')
            rsp.command(f'z1,{sym["_arm_init"]:x},4')
            for _ in range(8):
                rsp.command('s')
                result['stops'].append(control_registers(rsp.registers()))
            # The first genuine C prologue instruction must retire sequentially;
            # jumping into an exception vector is not a successful execution proof.
            result['arm_init_executed'] = int(result['stops'][0]['pc'],16) == sym['_arm_init']+4
            if not result['arm_init_executed']:
                raise ValueError('genuine arm_init instructions did not execute')
            # Do not describe a reached function boundary as a working subsystem.
            names = ('_arm_vm_init','_pmap_bootstrap','_kernel_bootstrap','_vm_mem_bootstrap',
                     '_vm_mem_init','_zone_bootstrap','_kmem_bootstrap','_ipc_bootstrap',
                     '_ipc_init','_sched_init','_bsd_init','_register_crypto_functions',
                     '_ums512_crypto_startup','_ums512_aes_selftest','_register_and_init_prng',
                     '_kernel_bootstrap_thread','_vm_commpage_init','_vm_commpage_text_init',
                     '_mac_policy_initmach','_trust_cache_runtime_init','_load_static_trust_cache',
                     '_machine_lockdown','_PE_lockdown_iokit',
                     '_ums512_runtime_selftest',
                     '_ums512_gic_init','_sleh_irq','_rtclock_intr','_ums512_irq_selftest',
                     '_ums512_scheduler_selftest',
                     '_ums512_security_init','_ums512_security_runtime_test',
                     '_vm_set_restrictions','_OSKextRemoveKextBootstrap',
                     '_bsd_autoconf','_IOKitBSDInit','_IOFindBSDRoot','_vfs_mountroot','_vfsinit',
                     '_kminit','_bsd_init_task',
                     '_IOKitInitializeTime','_clock_initialize_calendar','_bsd_bufferinit','_kauth_init',
                     '_mcache_init','_mbinit','_ml_wait_max_cpus','_ml_set_max_cpus',
                     '_ums512_qemu_finalize_cpu_topology','_IOMapperIOVMAlloc',
                     '_audit_init','_domaininit','_dlil_init','_skywalk_init','_sysctl_mib_init',
                     '_tcp_init','_aes_encrypt_key128','_aes_encrypt_key',
                     '_ums512_bsd_socket_selftest','_loopattach','_net_init_run','_inittodr',
                     '_ums512_hfs_register','_ums512_qemu_publish_root_storage',
                     '_hfs_mountroot','_hfs_mount','_hfs_vnop_ioctl','_hfs_vfs_root',
                     '_hfs_mounthfsplus','_dkstrategy',
                     '_ums512_qemu_hfs_root_auth','_devfs_kernel_mount',
                     '_ums512_qemu_rootfs_selftest',
                     '_bsd_utaskbootstrap','_bsd_ast','_load_init_program','_exec_activate_image',
                     '_load_machfile','_machine_thread_set_state','_cs_validate_page','_getpid',
                     '_ums512_pthread_register','_ums512_pthread_start','_pthread_kext_register',
                     '_pthread_init','__pthread_init',
                     '__ZN15RMXQemuPlatform5startEP9IOService',
                     '__ZN15RMXQemuPlatform9configureEP9IOService',
                     '_kmem_crypto_init','_Assert','_panic')
            boundaries = {sym[n]:n for n in names if n in sym}
            return_sp={}
            for address in boundaries:
                if rsp.command(f'Z1,{address:x},4') != 'OK':
                    raise RuntimeError('QEMU init-boundary breakpoint unavailable')
            deadline = time.monotonic()+result['observation_window_seconds']
            for _ in range(256):
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    result['bounded_run_timeout'] = True
                    break
                conn.settimeout(remaining)
                try:
                    rsp.command('c')
                except socket.timeout:
                    conn.sendall(b'\x03')
                    rsp.receive()
                    result['bounded_run_timeout'] = True
                regs = rsp.registers()
                name = boundaries.get(int(regs['pc'],16),'other stop')
                if name.startswith('return:') and int(regs['sp'],16)!=return_sp.get(int(regs['pc'],16)):
                    result.setdefault('foreign_return_addresses_ignored',[]).append(
                        dict(function=name[7:],expected_sp=hex(return_sp.get(int(regs['pc'],16),0)),**control_registers(regs)))
                    rsp.command(f'z1,{int(regs["pc"],16):x},4')
                    boundaries.pop(int(regs['pc'],16),None)
                    continue
                result['stops'].append({'boundary':name,**control_registers(regs)})
                if name=='_machine_thread_set_state':
                    flavor,count=int(regs['x1'],16)&0xffffffff,int(regs['x3'],16)&0xffffffff
                    pointer=int(regs['x2'],16)
                    if (flavor,count) in ((6,68),(1,70)):
                        state=bytes.fromhex(rsp.command(f'm{pointer:x},{count*4:x}'))
                        if flavor==1:
                            if struct.unpack_from('<II',state)!=(6,68): state=b''
                            else: state=state[8:]
                        if state:
                            user_sp,user_pc=struct.unpack_from('<QQ',state,248)
                            if 0x4000<=user_pc<0x800000000000 and user_pc%4==0:
                                result['proposed_user_entry']=dict(pc=hex(user_pc),sp=hex(user_sp),source='real ARM_THREAD_STATE64 setter')
                                for delta,label in ((0,'__user_entry'),(8,'__user_after_syscall'),(20,'__user_done')):
                                    address=user_pc+delta
                                    if address not in boundaries:
                                        if rsp.command(f'Z1,{address:x},4')!='OK': raise RuntimeError('user observation breakpoint unavailable')
                                        boundaries[address]=label
                    # Preserve the real setter breakpoint until init's state is
                    # installed; single-step original code, never write registers.
                    rsp.command(f'z1,{int(regs["pc"],16):x},4');rsp.command('s')
                    if rsp.command(f'Z1,{sym[name]:x},4')!='OK': raise RuntimeError('state setter rearm failed')
                    continue
                if name=='__user_entry':
                    pc=int(regs['pc'],16)
                    actual=bytes.fromhex(rsp.command(f'm{pc:x},8'))
                    if int(regs['cpsr'],16)&15 or actual!=struct.pack('<II',0xd2800290,0xd4001001):
                        raise RuntimeError('actual user entry is not EL0 owned getpid code')
                    rsp.command(f'z1,{pc:x},4');rsp.command('s');after=rsp.registers()
                    if int(after['pc'],16)!=pc+4 or int(after['x16'],16)!=20 or int(after['cpsr'],16)&15:
                        raise RuntimeError('first genuine EL0 instruction did not execute')
                    result['user_el0_execution_verified']=True
                    result['first_user_instruction']=dict(pc=hex(pc),instruction='mov x16,#20',after_pc=after['pc'],x16=20,cpsr=after['cpsr'])
                    continue
                if name=='__user_after_syscall':
                    if int(regs['cpsr'],16)&15 or int(regs['x0'],16)!=1 or int(regs['cpsr'],16)&0x20000000:
                        raise RuntimeError('real getpid syscall did not return PID1 successfully to EL0')
                    result['syscall_roundtrip_verified']=True
                    result['syscall_return']=dict(pc=regs['pc'],cpsr=regs['cpsr'],pid=1,syscall=20)
                    rsp.command(f'z1,{int(regs["pc"],16):x},4')
                    continue
                if name=='_cs_validate_page':
                    result['observed_page_validation_offset']=int(regs['x2'],16)
                    page_outputs=[int(regs[k],16) for k in ('x4','x5','x6')]
                if name=='return:_cs_validate_page':
                    values=[int.from_bytes(bytes.fromhex(rsp.command(f'm{a:x},4')),'little') for a in page_outputs]
                    result['native_code_page_validation']=dict(zip(('validated','tainted','nx'),values))
                if name=='return:_getpid': result['genuine_getpid_handler_returned']=True
                if '_ums512_lab_exec_proof' in sym and name in ('_panic','__user_done','return:_exec_activate_image'):
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_lab_exec_proof"]:x},40'))
                    result['lab_exec_runtime']=dict(zip(('exec_allowed','signature_allowed','files_verified','denials',
                        'vnode_negative_tests','reserved0','reserved1','reserved2'),struct.unpack('<8Q',raw)))
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_exec_denial_proof"]:x},20'))
                    result['actual_exec_denial_runtime']=dict(zip(('callbacks','regular_files','init_process','denied'),struct.unpack('<4Q',raw)))
                if name=='__user_done':
                    if int(regs['cpsr'],16)&15 or int(regs['x0'],16)!=0x515:
                        raise RuntimeError('EL0 did not verify syscall result and reach its success marker')
                    result['user_program_completed']=True
                    break
                if name.startswith('return:'):
                    result['returned_init_functions'].append(name[7:])
                if name=='_ums512_qemu_hfs_root_auth':
                    result.setdefault('root_auth_calls',[]).append(dict(
                        device=int(regs['x0'],16)&0xffffffff,
                        is_root=bool(int(regs['x1'],16)&0xffffffff),read_only=bool(int(regs['x2'],16)&0xffffffff)))
                if name=='return:_ums512_qemu_hfs_root_auth':
                    result.setdefault('root_auth_returns',[]).append(int(regs['x0'],16)&0xffffffff)
                if name in ('_bsd_init','_IOFindBSDRoot'):
                    inspect_crypto(rsp,sym,result)
                    if '_ums512_lab_exec_proof' in sym:
                        address=sym['_cs_process_enforcement_enable']
                        result['global_cs_enforcement']=int.from_bytes(bytes.fromhex(rsp.command(f'm{address:x},4')),'little')
                        result['global_cs_enforcement_mapping']=inspect_mapping(rsp,address,rsp.system_registers())
                if '_ums512_storage_proof' in sym and name in ('_Assert','_panic','other stop','_vfs_mountroot',
                        'return:_vfs_mountroot','_ums512_qemu_hfs_root_auth','_devfs_kernel_mount','_load_init_program'):
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_storage_proof"]:x},80'))
                    result['storage_runtime']=dict(zip(('started','image_authenticated','reads','bytes_read',
                        'writes_rejected','bounds_rejected','root_auth_ok','root_auth_denied',
                        'test_complete','test_reads','test_writes','test_bounds','test_access',
                        'test_crypto_negative','test_auth_negative','reserved'),struct.unpack('<16Q',raw)))
                    if result['storage_runtime']['test_complete'] and 'root_image_mappings' not in result:
                        system=rsp.system_registers()
                        begin,end=sym['_ums512_root_image'],sym['_ums512_root_image_end']
                        result['root_image_mappings']=[inspect_mapping(rsp,address,system)
                            for address in (begin,begin+(end-begin)//2,end-1)]
                        result['root_image_ro_nx_samples_verified']=all(p.get('valid') and p.get('read_only') and
                            p.get('privileged_execute_never') for p in result['root_image_mappings'])
                if name=='return:_vfs_mountroot':
                    result['vfs_mountroot_return']=int(regs['x0'],16)&0xffffffff
                    result['rootfs_mounted']=result['vfs_mountroot_return']==0
                if '_ums512_exec_denial_proof' in sym and name in ('_Assert','_panic','_load_init_program'):
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_exec_denial_proof"]:x},20'))
                    result['actual_exec_denial_runtime']=dict(zip(('callbacks','regular_files','init_process','denied'),
                                                                 struct.unpack('<4Q',raw)))
                if '_ums512_rootfs_proof' in sym and name in ('_Assert','_panic','other stop',
                        'return:_ums512_qemu_rootfs_selftest','_devfs_kernel_mount','_load_init_program'):
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_rootfs_proof"]:x},40'))
                    result['rootfs_vnode_runtime']=dict(zip(('magic','complete','reads','bytes',
                        'eof_checks','write_denials','missing_denials','nonroot_auth_denials'),struct.unpack('<8Q',raw)))
                if '_ums512_bsd_socket_proof' in sym and name in ('return:_ums512_bsd_socket_selftest','_panic','_IOFindBSDRoot'):
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_bsd_socket_proof"]:x},40'))
                    result['bsd_socket_runtime']=dict(zip(('magic','complete','phase','pairs','messages',
                        'bytes','empty_rejections','eof_checks'),struct.unpack('<8Q',raw)))
                    result['bsd_socket_runtime_tests_passed']=result['bsd_socket_runtime']==dict(
                        magic=0x524d584253445331,complete=1,phase=6,pairs=2,messages=12,bytes=1180,empty_rejections=4,eof_checks=1)
                    if name=='return:_ums512_bsd_socket_selftest' and not result['bsd_socket_runtime_tests_passed']:
                        raise RuntimeError('genuine BSD socket selftest returned without completed proof')
                if name in ('return:_machine_lockdown','_vm_set_restrictions','_bsd_init') and '_ums512_security_proof' in sym and 'security_lockdown_mappings' not in result:
                    system=rsp.system_registers()
                    protected={}
                    for symbol in ('_img4if','_amfi'):
                        address=sym[symbol]
                        value=int.from_bytes(bytes.fromhex(rsp.command(f'm{address:x},8')),'little')
                        protected[symbol[1:]+'_pointer']=inspect_mapping(rsp,address,system)
                        protected[symbol[1:]+'_table']=inspect_mapping(rsp,value,system)
                    result['security_lockdown_mappings']=protected
                    result['security_tables_read_only_nx']=all(
                        p.get('valid') and p.get('read_only') and p.get('privileged_execute_never') for p in protected.values())
                    if not result['security_tables_read_only_nx']:
                        raise RuntimeError('actual security interface VA mappings are not read-only/NX after stock lockdown')
                if rtc and name in ('_Assert','_panic','other stop','_bsd_init','_bsd_autoconf','_IOFindBSDRoot','_vfs_mountroot'):
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_platform_proof"]:x},40'))
                    result['platform_runtime']=dict(zip(('started','mmio_nubs','resource_ranges','rtc_identity',
                        'rtc_reads','rtc_writes','rtc_tick_verified','unsupported_resource_requests'),struct.unpack('<8Q',raw)))
                    if '_ums512_cpu_topology_proof' in sym:
                        raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_cpu_topology_proof"]:x},40'))
                        result['cpu_topology_runtime']=dict(zip(('published','num_cpus','max_cpu_id','boot_cpu_id',
                            'boot_phys_id','current_affinity','machine_max_cpus','reserved0'),struct.unpack('<8Q',raw)))
                if uart and name in ('_panic','_bsd_init','return:_ums512_security_runtime_test'):
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_uart_proof"]:x},40'))
                    result['uart_runtime']=dict(zip(('initialized','tx_bytes','rx_bytes','clock_hz','divisor64',
                                                    'physical','size','identity_verified'),struct.unpack('<8Q',raw)))
                    serial=(out/'serial.log').read_bytes()[:1024*1024]
                    result['uart_ready_marker_received']=b'RMX-QEMU: PL011 console ready' in serial
                if name == '_trust_cache_runtime_init':
                    observed = {}
                    for key in ('_img4if','_amfi'):
                        if key in sym:
                            value = int.from_bytes(bytes.fromhex(rsp.command(f'm{sym[key]:x},8')),'little')
                            observed[key] = {'address':hex(sym[key]),'value':hex(value)}
                    result['security_interface_observations'] = observed
                if '_ums512_security_proof' in sym and name in ('return:_ums512_security_runtime_test','_panic','_bsd_init'):
                    raw=bytes.fromhex(rsp.command(f'm{sym["_ums512_security_proof"]:x},40'))
                    result['security_runtime_tests']=dict(zip(
                        ('registered','firmware_cases','cache_cases','query_cases','policy_cases',
                         'stock_runtime_ready','complete','execution_quarantined'),struct.unpack('<8Q',raw)))
                    result['trust_cache_runtime_init_completed']= '_trust_cache_runtime_init' in result['returned_init_functions']
                    result['security_runtime_tests_passed']=(result['trust_cache_runtime_init_completed'] and
                        result['security_runtime_tests']==dict(registered=1,firmware_cases=42,cache_cases=30,
                            query_cases=25,policy_cases=7,stock_runtime_ready=1,complete=1,execution_quarantined=1))
                if runtime_requested and name in ('return:_ums512_runtime_selftest','_panic'):
                    for symbol,fields in (
                        ('_ums512_irq_proof',('initialized','irq_entries','timer_interrupts','timer_returns','spurious','sgi_interrupts','last_intid','distributor_control')),
                        ('_ums512_timer_proof',('complete','callbacks','interrupt_context','earliest','observed','sgi_sent','reserved0','reserved1')),
                        ('_ums512_scheduler_proof',('complete','worker_entries','different_thread','roundtrips','timed_out','termination_requested','reserved0','reserved1'))):
                        if symbol in sym:
                            raw=bytes.fromhex(rsp.command(f'm{sym[symbol]:x},40'))
                            result[symbol[1:]]=dict(zip(fields,struct.unpack('<8Q',raw)))
                    values = struct.unpack('<8Q',bytes.fromhex(rsp.command(f'm{sym["_ums512_runtime_proof"]:x},40')))
                    result['kernel_runtime_tests'] = dict(zip(
                        ('magic','complete','phase','vm_allocations','verified_bytes','ports','message_roundtrips','trust_checks'),values))
                    result['kernel_runtime_tests']['magic'] = hex(values[0])
                    result['kernel_runtime_tests_passed'] = (values[:2] == (0x524d58584e555431,1) and values[7]==33 and
                        result.get('ums512_timer_proof',{}).get('complete')==1 and
                        result.get('ums512_scheduler_proof',{}).get('complete')==1)
                if name in ('_kmem_crypto_init','_register_crypto_functions'):
                    inspect_crypto(rsp,sym,result)
                if name == '_Assert':
                    result['assertion_reached'] = True
                    result['assertion_file'] = image_cstring(data,report['segments'],int(regs['x0'],16))
                    result['assertion_line'] = int(regs['x1'],16) & 0xffffffff
                    result['assertion_expression'] = image_cstring(data,report['segments'],int(regs['x2'],16))
                if name == '_panic':
                    result['panic_reached'] = True
                    panic_format = image_cstring(data,report['segments'],int(regs['x0'],16),2048)
                    if panic_format:
                        result['panic_format_from_audited_kernel'] = panic_format[:512]
                        result['panic_format_truncated'] = len(panic_format)>512
                    for i in range(6):
                        text = image_cstring(data,report['segments'],int(regs[f'x{i}'],16))
                        if text:
                            key = 'panic_format_from_audited_kernel' if i == 0 else f'panic_x{i}_string_from_audited_kernel'
                            result[key] = text
                    # Darwin ARM64 variadic arguments are passed on the stack.
                    # Read only this bounded QEMU-generated argument block;
                    # export source strings and numeric words, not a raw dump.
                    try:
                        fault = bool(panic_format and panic_format.startswith('%s at pc '))
                        # Decode only described arguments, never unused stack
                        # slots left by prior crypto operations. The fixed abort
                        # ABI supplies control state; plain decorated panics
                        # supply exactly a source filename and line number.
                        plain = bool(panic_format and panic_format.endswith(' @%s:%d') and
                                     '%' not in panic_format[:-len(' @%s:%d')])
                        security_message=panic_format=='QEMU lab security runtime test: %s @%s:%d'
                        hygiene=panic_format=='%s for %llu nanoseconds (start = %llu, now = %llu, timeout = %llu ns%s) @%s:%d'
                        init_failure=panic_format=='Process 1 exec of %s failed, errno %d @%s:%d'
                        length = 336 if fault else 64 if hygiene else 32 if init_failure else 24 if security_message else 16 if plain else 0
                        block = bytes.fromhex(rsp.command(f'm{int(regs["sp"],16):x},{length:x}')) if length else b''
                        values = (struct.unpack('<5Q',block[:40]) if fault else
                                  struct.unpack_from('<QQI',block) if security_message else
                                  plain_panic_arguments(block) if plain else
                                  interrupt_mask_panic_arguments(block) if hygiene else ())
                        if init_failure:
                            path,error,source,line=init_process_panic_arguments(block)
                            # Both strings must belong to the audited Mach-O;
                            # no arbitrary vnode/path buffers are read/exported.
                            result['first_process_exec_failure']=dict(
                                path=image_cstring(data,report['segments'],path),errno=error,
                                source=image_cstring(data,report['segments'],source),line=line)
                        result['panic_stack_argument_words'] = [hex(v) for v in values]
                        result['panic_stack_source_strings'] = [image_cstring(data,report['segments'],v) for v in values]
                        if hygiene:
                            reason=image_cstring(data,report['segments'],values[0])
                            source=image_cstring(data,report['segments'],values[5])
                            if reason not in ('Interrupts held disabled','Stackshot disabled interrupts') or source != 'machine_routines_common.c':
                                raise ValueError('interrupt-mask panic static strings mismatch')
                            result['interrupt_mask_watchdog']=dict(reason=reason,elapsed_ns=values[1],
                                start_ticks=values[2],now_ticks=values[3],timeout_ns=values[4],source=source,line=values[6])
                        if fault:
                            # Exact panic_with_thread_kernel_state argument order
                            # in pinned sleh.c. Darwin variadic arguments use
                            # eight-byte slots even for these two u32 values.
                            state = struct.unpack_from('<38Q',block)
                            cpsr,esr,far = struct.unpack_from('<QQQ',block,304)
                            cpsr,esr = cpsr & 0xffffffff,esr & 0xffffffff
                            if state[1] != state[37] or state[2] != state[35]:
                                raise ValueError('saved-state panic ABI mismatch')
                            result['kernel_fault'] = dict(pc=hex(state[1]),lr=hex(state[2]),
                                sp=hex(state[36]),cpsr=hex(cpsr),esr=hex(esr),far=hex(far))
                            pc = state[1]
                            owner = next(s for s in report['segments'] if s['vmaddr'] <= pc < s['vmaddr']+s['filesize'])
                            off = owner['fileoff']+pc-owner['vmaddr']
                            word = struct.unpack_from('<I',data,off)[0]
                            guest = bytes.fromhex(rsp.command(f'm{pc:x},4'))
                            result['fault_instruction'] = {'word':hex(word),'matches_audited_image':guest == data[off:off+4]}
                            if word & 0xffc00000 == 0xf9400000:
                                base = (word >> 5) & 31
                                registers = [*state[5:34],state[34],state[35],state[36]]
                                effective = (registers[base]+8*((word >> 10) & 4095)) & ((1<<64)-1)
                                result['fault_instruction'].update(mnemonic='LDR X, [Xn, #imm]',
                                    base_register=base,base_value=hex(registers[base]),
                                    destination_register=word & 31,effective_address=hex(effective),
                                    matches_far=effective == far)
                            inspect_crypto(rsp,sym,result)
                            system = result['crypto_registration_observations'][-1].get('system_registers',{})
                            if system:
                                result['fault_pc_mapping'] = inspect_mapping(rsp,pc,system)
                                result['fault_address_mapping'] = inspect_mapping(rsp,far,system)
                    except (ValueError,RuntimeError) as error:
                        result['panic_argument_decode_error'] = str(error)
                if name in ('_Assert','_panic','other stop'):
                    break
                rsp.command(f'z1,{int(regs["pc"],16):x},4')
                if name.startswith('return:'):
                    # Startup callbacks reuse one dispatcher LR. Re-arm that
                    # address for the next function rather than retaining a
                    # stale return name after its hardware breakpoint is gone.
                    boundaries.pop(int(regs['pc'],16),None)
                    if name=='return:_ums512_qemu_hfs_root_auth' and result['root_auth_returns'][-1]:
                        # Observe the real successful BSD root-auth call after
                        # the deliberately rejected native selftest requests.
                        address=sym['_ums512_qemu_hfs_root_auth']
                        if rsp.command(f'Z1,{address:x},4')!='OK':
                            raise RuntimeError('root-auth observation breakpoint unavailable')
                elif name not in ('_kernel_bootstrap','_kernel_bootstrap_thread'):
                    # A function entry does not prove initialization completed.
                    # Observe its real caller return address without changing LR.
                    address = int(regs['lr'],16)
                    if address not in boundaries:
                        boundaries[address] = 'return:'+name
                        return_sp[address]=int(regs['sp'],16)
                        if rsp.command(f'Z1,{address:x},4') != 'OK':
                            raise RuntimeError('QEMU init-return breakpoint unavailable')
            else:
                result['boundary_limit_reached']=True
            if result.get('assertion_reached'):
                raise RuntimeError('genuine XNU assertion: '+str(result.get('assertion_expression'))+
                                   ' at '+str(result.get('assertion_file'))+':'+str(result.get('assertion_line')))
            if result.get('kernel_fault'):
                raise RuntimeError('genuine XNU data/instruction abort; inspect exact saved-state evidence')
            if runtime_requested and not result.get('kernel_runtime_tests_passed'):
                raise RuntimeError('requested genuine kernel VM/IPC tests did not complete; inspect recorded panic/phase')
            if '_ums512_security_proof' in sym and not result.get('security_runtime_tests_passed'):
                raise RuntimeError('genuine security runtime checks did not complete; inspect recorded panic/proof')
            if uart and (not result.get('uart_ready_marker_received') or
                         result.get('uart_runtime',{}).get('identity_verified')!=1):
                raise RuntimeError('QEMU PL011 identity/TX marker not verified')
            if rtc and (result.get('platform_runtime',{}).get('started')!=1 or
                        result.get('platform_runtime',{}).get('rtc_tick_verified')!=1):
                raise RuntimeError('QEMU Platform Expert/PL031 runtime did not complete')
            if '_ums512_cpu_topology_proof' in sym and result.get('cpu_topology_runtime')!=dict(
                published=1,num_cpus=1,max_cpu_id=0,boot_cpu_id=0,boot_phys_id=0,current_affinity=0,machine_max_cpus=1,reserved0=0):
                raise RuntimeError('QEMU actual UP CPU enumeration publication did not complete')
            if '_ums512_storage_proof' in sym:
                storage=result.get('storage_runtime',{})
                if any(storage.get(k)!=v for k,v in dict(test_complete=1,test_reads=2,test_writes=1,
                        test_bounds=3,test_access=2,test_crypto_negative=1,test_auth_negative=3).items()):
                    raise RuntimeError('genuine readonly block transport tests did not complete')
                if not result.get('root_image_ro_nx_samples_verified'):
                    raise RuntimeError('immutable root image live RO/NX samples were not verified')
                if not result.get('rootfs_mounted') or not result.get('rootfs_vnode_runtime',{}).get('complete') or not storage.get('root_auth_ok'):
                    raise RuntimeError('genuine authenticated HFS root mount/vnode operations did not complete')
                result['rootfs_runtime_tests_passed']=True
                if '_ums512_lab_exec_proof' in sym:
                    lab=result.get('lab_exec_runtime',{})
                    enforcement=result.get('global_cs_enforcement_mapping',{})
                    if result.get('global_cs_enforcement')!=1 or not enforcement.get('read_only') or not enforcement.get('privileged_execute_never'):
                        raise RuntimeError('stock global code signing enforcement must be enabled and locked RO/NX')
                    if not all(result.get(k) for k in ('user_el0_execution_verified','syscall_roundtrip_verified',
                               'genuine_getpid_handler_returned','user_program_completed')):
                        raise RuntimeError('genuine signed Mach-O/EL0/syscall roundtrip did not complete')
                    if lab.get('exec_allowed')!=1 or lab.get('signature_allowed',0)<1 or lab.get('files_verified',0)<2 or lab.get('vnode_negative_tests')!=3:
                        raise RuntimeError('real CMS/CD signature attachment or untrusted vnode rejection not confirmed')
                    page=result.get('native_code_page_validation',{})
                    if not page.get('validated') or page.get('tainted') or page.get('nx'):
                        raise RuntimeError('native executable-page validation not observed')
                    if result.get('panic_reached'): raise RuntimeError('unexpected panic in signed user execution profile')
                elif result.get('panic_format_from_audited_kernel'):
                    failure=result.get('first_process_exec_failure',{})
                    if '_ums512_exec_denial_proof' in sym:
                        result['expected_unsigned_init_denial']=(failure.get('path')=='/sbin/launchd' and
                            failure.get('errno')==80 and result.get('actual_exec_denial_runtime')==dict(
                                callbacks=1,regular_files=1,init_process=1,denied=1))
                        if not result['expected_unsigned_init_denial']:
                            raise RuntimeError('actual unsigned init must reach the mandatory MAC callback and fail EAUTH')
                    else:
                        result['expected_missing_init_boundary']=failure.get('path')=='/sbin/launchd' and failure.get('errno')==2
                    if not (result.get('expected_missing_init_boundary') or result.get('expected_unsigned_init_denial')):
                        raise RuntimeError('unexpected XNU panic after root mount; inspect recorded format/arguments')
                elif '_ums512_exec_denial_proof' in sym:
                    raise RuntimeError('actual unsigned init exec-denial boundary was not reached')
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        result['bsd_startup_returned']='_bsd_init' in result['returned_init_functions']
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        log.close()
        if uart and (out/'serial.log').exists():
            serial=(out/'serial.log').read_bytes()[:1024*1024]
            start=serial.rfind(b'Waiting on ')
            root_matching=serial[start:start+4096] if start>=0 else b''
            result['bsd_root_console_observations']=dict(
                iobsd_resource_timeout=b'!BSD' in serial,root_matching_printed=start>=0,
                root_matching_iomedia=b'IOMedia' in root_matching,
                root_matching_apple_hfs=b'Apple_HFS' in root_matching)
        ordered = sorted((address,name) for name,address in sym.items() if address)
        from bisect import bisect_right
        for stop in [result.get('arm_init_entry',{}),result.get('kernel_fault',{}),*result['stops']]:
            for register in ('pc','lr'):
                if register not in stop:
                    continue
                address = int(stop[register],16)
                index = bisect_right(ordered,(address,chr(0x10ffff)))-1
                if index >= 0 and address-ordered[index][0] < 0x10000:
                    base,name = ordered[index]
                    stop[register+'_symbol'] = name+'+'+hex(address-base)
        decoded = {}
        for i,word in enumerate(result.get('panic_stack_argument_words',[])):
            address = int(word,16)
            index = bisect_right(ordered,(address,chr(0x10ffff)))-1
            if index >= 0 and address-ordered[index][0] < 0x10000:
                base,name = ordered[index]
                decoded[str(i)] = name+'+'+hex(address-base)
        if decoded:
            result['panic_stack_address_symbols'] = decoded
        if result.get('error'):
            tail = (out/'qemu.log').read_bytes()[-4096:].decode('utf-8',errors='replace')
            if tail:
                print('QEMU diagnostic tail: '+tail,flush=True)
        (out/'execution.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2),flush=True)


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('kernel',type=Path)
    p.add_argument('--record',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--qemu',default=shutil.which('qemu-system-aarch64'))
    p.add_argument('--clang',default=shutil.which('clang'))
    a=p.parse_args()
    if not a.qemu or not a.clang:
        p.error('real QEMU and Mach-O capable Clang are required')
    execute(a.kernel.resolve(),a.record,a.out.resolve(),a.qemu,a.clang)
