"""Offline UMS512 facts/IRQ and conservative RAM exclusions; never a device launcher."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1 << 64


def extent(value):
    base, size = int(value['base'], 0), int(value['size'], 0)
    if base < 0 or size <= 0 or base + size >= LIMIT:
        raise ValueError('invalid/overflowing physical extent')
    if 'end_exclusive' in value and int(value['end_exclusive'], 0) != base + size:
        raise ValueError('inconsistent physical extent')
    return base, base + size


def gic_irq(cells):
    # Pinned vendor Documentation/devicetree/bindings/interrupt-controller/arm,gic-v3.txt.
    # This board uses three cells, no fourth-cell PPI affinity or legacy CPU mask.
    if len(cells) != 3 or any(type(v) is not int or not 0 <= v <= 0xffffffff for v in cells):
        raise ValueError('GIC IRQ requires exactly three uint32 cells')
    kind, number, flags = cells
    if kind not in (0, 1) or number > (987 if kind == 0 else 15) or flags not in (1, 4):
        raise ValueError('unsupported GIC type, number or trigger flags')
    intid = number + (32 if kind == 0 else 16)
    return dict(intid=intid, trigger='edge-rising' if flags == 1 else 'level-high',
                icfgr_offset=0xc00 + (intid // 16) * 4, icfgr_shift=(intid % 16) * 2,
                icfgr_value=2 if flags == 1 else 0)


def profile(board):
    # A well-formed range is not necessarily the range observed for this board.
    # Pin the complete envelope, including its final missing 4KiB; never widen
    # it to a rounded marketing "4GB" or inherit a QEMU RAM bank.
    if [extent(r) for r in board['ram']] != [(0x80000000, 0x17ffff000)]:
        raise ValueError('RAM envelope differs from pinned UMS512 baseline')
    def one(compatible):
        matches = [d for d in board['devices'] if compatible in d['compatible']]
        if len(matches) != 1: raise ValueError('missing/ambiguous hardware binding: ' + compatible)
        return matches[0]
    def regs(node, count):
        if len(node['reg']) != count: raise ValueError('wrong register bank count')
        return [extent(v) for v in node['reg']]
    gic, timer, psci = map(one, ('arm,gic-v3', 'arm,armv8-timer', 'arm,psci-0.2'))
    gr = regs(gic, 2)
    stride = gic['redistributor-stride']
    if gr != [(0x12000000, 0x12020000), (0x12040000, 0x12140000)] or stride != [0, 0x20000]:
        raise ValueError('not the published UMS512 GIC layout; QEMU addresses forbidden')
    if psci['method'] != ['smc']: raise ValueError('unconfirmed PSCI conduit')
    if gic['interrupts'] != [1, 9, 4]:
        raise ValueError('GIC maintenance IRQ differs from pinned UMS512 baseline')
    t = timer['interrupts']
    if len(t) != 12: raise ValueError('expected four ordered architected timer IRQs')
    timer_irqs = {name: gic_irq(t[i*3:i*3+3]) for i, name in enumerate(
        ('secure_physical', 'nonsecure_physical', 'virtual', 'hypervisor'))}
    if [x['intid'] for x in timer_irqs.values()] != [29, 30, 27, 26] or any(t[i] != 4 for i in (2, 5, 8, 11)):
        raise ValueError('timer binding differs from pinned UMS512 source')
    cpus = []
    for c in board['cpus']:
        if len(c['mpidr']) != 1 or c['enable-method'] != ['psci'] or c['compatible'] not in (['arm,cortex-a55', 'arm,armv8'], ['arm,cortex-a75', 'arm,armv8']):
            raise ValueError('unconfirmed CPU binding')
        affinity = int(c['mpidr'][0], 0)
        if affinity & ~0xff00ffffff: raise ValueError('reserved MPIDR affinity bits')
        cpus.append(dict(affinity=hex(affinity), core=c['compatible'][0]))
    if len(cpus) != 8 or len({c['affinity'] for c in cpus}) != 8:
        raise ValueError('missing/duplicate CPU affinities')
    expected = {hex(i*0x100): 'arm,cortex-a55' if i < 6 else 'arm,cortex-a75' for i in range(8)}
    if {c['affinity']: c['core'] for c in cpus} != expected:
        raise ValueError('CPU affinity/core map differs from pinned UMS512 source')
    uart = next((d for d in board['devices'] if d['path'] == board['stdout_node']), None)
    if not uart or 'sprd,sc9836-uart' not in uart['compatible'] or uart['status'] != ['okay']:
        raise ValueError('stdout is not an enabled SPRD UART')
    ur = regs(uart, 1)[0]
    if ur != (0x70100000, 0x70100100): raise ValueError('unconfirmed stdout register bank')
    if uart['interrupts'] != [0, 3, 4]:
        raise ValueError('UART1 IRQ differs from pinned UMS512 baseline')
    emmc = [d for d in board['devices'] if 'sprd,sdhc-r11p1' in d['compatible'] and d.get('bus-width') == [8]]
    if len(emmc) != 1 or emmc[0]['status'] != ['okay'] or regs(emmc[0], 1)[0] != (0x71400000, 0x71401000):
        raise ValueError('missing/ambiguous eMMC SDHCI binding')
    if emmc[0]['interrupts'] != [0, 10, 4]:
        raise ValueError('eMMC IRQ differs from pinned UMS512 baseline')
    reserved = [v for n in board['reserved_memory'] for v in n['reg']] + board['memreserve']
    if any(not n['reg'] for n in board['reserved_memory']):
        raise ValueError('unresolved dynamic reservation: no allocatable RAM claim')
    for v in board['ram'] + reserved: extent(v)
    return dict(scope='Offline descriptor from analysis-only allowlist, cross-checked with pinned public vendor source',
        hardware_verified=False, m1='NO-GO', board_fdt_sha256=board['sha256'],
        gic=dict(distributor=hex(gr[0][0]), redistributors=hex(gr[1][0]),
                 redistributor_bytes=hex(gr[1][1]-gr[1][0]), stride=hex(0x20000),
                 maintenance=gic_irq(gic['interrupts']), security_state='UNVERIFIED; no controller writes permitted'),
        timer=timer_irqs, cntfrq_hz=None, psci=dict(conduit='smc', runtime_version=None, cpu_on_verified=False),
        cpus=cpus, uart=dict(base=hex(ur[0]), size=hex(ur[1]-ur[0]), irq=gic_irq(uart['interrupts']),
            txd_offset=0, status_offset=12, tx_fifo_count_mask=0xff00, clocks_pins_baud_verified=False),
        emmc=dict(base='0x71400000', size='0x1000', bus_width=8, irq=gic_irq(emmc[0]['interrupts']),
                  driver_implemented=False), reserved=reserved)


def ram_windows(board, extra=(), page=16384):
    if page not in (4096, 16384): raise ValueError('unsupported granule')
    profile(board)  # Reject a different SoC, unresolved dynamic pools and malformed facts.
    excluded = [extent(v) for n in board['reserved_memory'] for v in n['reg']]
    excluded += [extent(v) for v in board['memreserve']] + [extent(v) for v in extra]
    excluded = sorted((a & -page, (b + page-1) & -page) for a, b in excluded)
    merged = []
    for a, b in excluded:
        if merged and a <= merged[-1][1]: merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else: merged.append((a, b))
    result = []
    ram = sorted(extent(v) for v in board['ram'])
    if any(a[1] > b[0] for a, b in zip(ram, ram[1:])): raise ValueError('overlapping RAM banks')
    for a, b in ram:
        cursor, end = (a + page-1) & -page, b & -page
        for low, high in merged:
            if low >= end: break
            if high <= cursor: continue
            if low > cursor: result.append((cursor, low))
            cursor = max(cursor, high)
        if cursor < end: result.append((cursor, end))
    return [dict(base=hex(a), size=hex(b-a), end_exclusive=hex(b)) for a, b in result]


def header(board):
    p = profile(board)
    ram = board['ram']
    if len(ram) != 1: raise ValueError('component ABI requires one RAM envelope')
    values = dict(RAM_BASE=ram[0]['base'], RAM_END=ram[0]['end_exclusive'],
        GICD_BASE=p['gic']['distributor'], GICR_BASE=p['gic']['redistributors'],
        GICR_SIZE=p['gic']['redistributor_bytes'], GICR_STRIDE=p['gic']['stride'],
        VTIMER_INTID=p['timer']['virtual']['intid'])
    text = '/* Validated offline UMS512 facts; no live ownership or MMIO permission. */\n'
    text += ''.join(f'#define UMS512_{k} {v}ULL\n' for k, v in values.items())
    text += 'static const struct ums512_extent ums512_reserved[] = {\n'
    text += ''.join(f'    {{{r["base"]}ULL, {r["size"]}ULL}},\n' for r in p['reserved']) + '};\n'
    text += 'static const uint64_t ums512_cpu_affinities[] = {' + ','.join(c['affinity']+'ULL' for c in p['cpus']) + '};\n'
    text += 'static const uint16_t ums512_cpu_parts[] = {' + ','.join('0xd05' if c['core']=='arm,cortex-a55' else '0xd0a' for c in p['cpus']) + '};\n'
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'out/ums512-target/report.json')
    args = parser.parse_args()
    path = ROOT/'boards/ums512-hardware.json'
    b = json.loads(path.read_text())
    historical = json.loads((ROOT/'docs/m05-memory.json').read_text())
    p = profile(b)
    p.update(board_allowlist_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        static_exclusion_windows=ram_windows(b),
        historical_union_exclusion_windows=ram_windows(b, historical['regions']),
        selected_payload_address=None, approved_for_hardware=False,
        limits=['Historical union is conservative, not a live free-memory map.',
                'Loader BSS/heap/stack/FDT/initrd/DMA/secure access remain unverified.',
                'Linux x0=FDT and XNU x0=boot_args are distinct handoff ABIs.',
                'No EL2 transition, device driver execution or boot container is produced.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(p, indent=2)+'\n', encoding='utf-8', newline='\n')
    print('Validated UMS512 descriptor and RAM exclusions; M1 NO-GO; '+str(args.output))


if __name__ == '__main__': main()
