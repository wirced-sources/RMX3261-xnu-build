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

from fdt import FDT
from macho_kernel import audit, mapping, bootstrap_coverage


def align(n, a=0x4000):
    return (n + a - 1) & -a


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
        indices = [(f'x{i}',i) for i in range(6)] + [('x12',12),('lr',30),('sp',31),('pc',32)]
        return {name: hex(struct.unpack_from('<Q', data, i*8)[0]) for name,i in indices}


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
    memory = [tree.reg(n) for n in tree.nodes.values() if n.props.get('device_type') == b'memory\0']
    gics = [tree.reg(n) for n in tree.nodes.values() if 'arm,gic-v3' in n.strings('compatible')]
    if memory != [[(0x40000000, 0x20000000)]] or len(gics) != 1 or len(gics[0]) != 2:
        raise ValueError('unexpected QEMU virt RAM/GIC layout')
    pa, mem = memory[0][0]
    gicd, gicr = gics[0]
    va = min(s['vmaddr'] for s in report['segments'] if s['initprot'] and s['vmsize']) & -0x2000000
    end = max(s['vmaddr']+s['vmsize'] for s in report['segments'] if s['initprot'])
    adt_pa = align(pa+end-va)
    adt = node('device-tree', [('model',b'qemu,virt\0')], [
        node('chosen', [('dram-base',struct.pack('<Q',pa)),('dram-size',struct.pack('<Q',mem)),('random-seed',os.urandom(64))], [node('memory-map')]),
        node('cpus', children=[node('cpu0',[('device_type',b'cpu\0'),('state',b'running\0'),('reg',struct.pack('<I',0)),('timebase-frequency',struct.pack('<I',0))])]),
        node('arm-io',[('device_type',b'qemu,virt\0'),('ranges',struct.pack('<3Q',0,gicd[0],gicr[0]+gicr[1]-gicd[0]))], [node('gic',[('reg',struct.pack('<4Q',0,gicd[1],gicr[0]-gicd[0],gicr[1]))])])])
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
    proc = subprocess.Popen([*base_cmd,'-display','none','-serial','none','-monitor','none','-no-reboot','-S',
        '-gdb',f'tcp:127.0.0.1:{port}','-kernel',str(image),'-device',f'loader,file={out / "kernel.physical.bin"},addr={header_pa:#x},force-raw=on'],stdout=log,stderr=log)
    result = {'kernel_sha256':report['sha256'],'arm_init_executed':False,
              'kernel_boot_completed':False,'hardware_verified':False,'stops':[],
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
                result['stops'].append({'boundary':'timeout before arm_init',**rsp.registers()})
                raise RuntimeError('bounded run stopped before genuine arm_init; inspect recorded PC/SP/x0')
            before = rsp.registers()
            result['arm_init_entry'] = before
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
                result['stops'].append(rsp.registers())
            # The first genuine C prologue instruction must retire sequentially;
            # jumping into an exception vector is not a successful execution proof.
            result['arm_init_executed'] = int(result['stops'][0]['pc'],16) == sym['_arm_init']+4
            if not result['arm_init_executed']:
                raise ValueError('genuine arm_init instructions did not execute')
            # Do not describe a reached function boundary as a working subsystem.
            names = ('_arm_vm_init','_pmap_bootstrap','_kernel_bootstrap','_vm_mem_bootstrap',
                     '_vm_mem_init','_zone_bootstrap','_kmem_bootstrap','_ipc_bootstrap',
                     '_ipc_init','_sched_init','_bsd_init','_Assert','_panic')
            boundaries = {sym[n]:n for n in names if n in sym}
            for address in boundaries:
                if rsp.command(f'Z1,{address:x},4') != 'OK':
                    raise RuntimeError('QEMU init-boundary breakpoint unavailable')
            deadline = time.monotonic()+45
            for _ in range(32):
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    result['bounded_run_timeout'] = True
                    break
                conn.settimeout(min(15,remaining))
                try:
                    rsp.command('c')
                except socket.timeout:
                    conn.sendall(b'\x03')
                    rsp.receive()
                    result['bounded_run_timeout'] = True
                regs = rsp.registers()
                name = boundaries.get(int(regs['pc'],16),'other stop')
                result['stops'].append({'boundary':name,**regs})
                if name == '_Assert':
                    result['assertion_reached'] = True
                    result['assertion_file'] = image_cstring(data,report['segments'],int(regs['x0'],16))
                    result['assertion_line'] = int(regs['x1'],16) & 0xffffffff
                    result['assertion_expression'] = image_cstring(data,report['segments'],int(regs['x2'],16))
                if name == '_panic':
                    result['panic_reached'] = True
                    for i in range(6):
                        text = image_cstring(data,report['segments'],int(regs[f'x{i}'],16))
                        if text:
                            key = 'panic_format_from_audited_kernel' if i == 0 else f'panic_x{i}_string_from_audited_kernel'
                            result[key] = text
                    # Darwin ARM64 variadic arguments are passed on the stack.
                    # Read only this bounded QEMU-generated argument block;
                    # export source strings and numeric words, not a raw dump.
                    try:
                        block = bytes.fromhex(rsp.command(f'm{int(regs["sp"],16):x},40'))
                        values = struct.unpack('<8Q',block)
                        result['panic_stack_argument_words'] = [hex(v) for v in values]
                        result['panic_stack_source_strings'] = [image_cstring(data,report['segments'],v) for v in values]
                    except (ValueError,RuntimeError) as error:
                        result['panic_argument_decode_error'] = str(error)
                if name in ('_Assert','_panic','other stop'):
                    break
                rsp.command(f'z1,{int(regs["pc"],16):x},4')
                if name.startswith('return:'):
                    result['returned_init_functions'].append(name[7:])
                elif name != '_kernel_bootstrap':
                    # A function entry does not prove initialization completed.
                    # Observe its real caller return address without changing LR.
                    address = int(regs['lr'],16)
                    if address not in boundaries:
                        boundaries[address] = 'return:'+name
                        if rsp.command(f'Z1,{address:x},4') != 'OK':
                            raise RuntimeError('QEMU init-return breakpoint unavailable')
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        log.close()
        ordered = sorted((address,name) for name,address in sym.items() if address)
        from bisect import bisect_right
        for stop in [result.get('arm_init_entry',{}),*result['stops']]:
            for register in ('pc','lr'):
                if register not in stop:
                    continue
                address = int(stop[register],16)
                index = bisect_right(ordered,(address,chr(0x10ffff)))-1
                if index >= 0 and address-ordered[index][0] < 0x10000:
                    base,name = ordered[index]
                    stop[register+'_symbol'] = name+'+'+hex(address-base)
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
