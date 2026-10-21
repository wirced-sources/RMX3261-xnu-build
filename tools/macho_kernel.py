"""Strict offline acceptance for a future plain-arm64 XNU executable.

No loading, fixup application, PA allocation or hardware access. A structural
PASS is not proof that the input is XNU or that its code can run on UMS512.
Unresolved symbols, dyld dependencies and unprocessed fixups fail closed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

U64 = 1 << 64


def bounded(offset, size, limit):
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        raise ValueError("range outside file/address space")


def audit(data, page=0x4000):
    if page != 0x4000:
        raise ValueError("only proposed 16K kernel policy is implemented")
    bounded(0, 32, len(data))
    magic, cpu, sub, kind, count, size, flags, reserved = struct.unpack_from("<8I", data)
    if (magic, cpu, sub, kind, reserved) != (0xfeedfacf, 0x100000c, 0, 2, 0):
        raise ValueError("expected plain ARM64 MH_EXECUTE, not arm64e/object/dylib/fileset")
    bounded(32, size, len(data))
    end = 32 + size
    at, entry, symtab = 32, None, None
    segments, section_count = [], 0
    for _ in range(count):
        bounded(at, 8, end)
        cmd, length = struct.unpack_from("<II", data, at)
        if length < 8 or length % 8:
            raise ValueError("invalid load-command size/alignment")
        bounded(at, length, end)
        if cmd == 0x19:
            if length < 72:
                raise ValueError("short LC_SEGMENT_64")
            name = data[at + 8:at + 24].split(b"\0")[0].decode("ascii")
            va, mem, off, stored, maximum, initial, nsect, segflags = struct.unpack_from("<4Q4I", data, at + 24)
            if length != 72 + 80 * nsect:
                raise ValueError("segment section table mismatch")
            section_count += nsect
            bounded(va, mem, U64)
            bounded(off, stored, len(data))
            if stored > mem or va % page or off % page or mem % page:
                raise ValueError("invalid segment size or 16K alignment")
            if maximum & ~7 or initial & ~maximum or initial & 6 == 6:
                raise ValueError("invalid or writable/executable segment protections")
            for i in range(nsect):
                section = at + 72 + i * 80
                sectva, sectsize, sectoff, align, relocoff, nreloc, sectflags = struct.unpack_from("<QQ5I", data, section + 32)
                bounded(sectva - va, sectsize, mem)
                if align > 63 or nreloc:
                    raise ValueError("invalid alignment or remaining section relocations")
                if sectflags & 0xff not in (1, 0xc, 0x12):  # zero-fill section types
                    bounded(sectoff - off, sectsize, stored)
            segments.append({"name": name, "vmaddr": va, "vmsize": mem, "fileoff": off,
                             "filesize": stored, "maxprot": maximum, "initprot": initial})
        elif cmd == 5:
            if entry is not None or length != 288:
                raise ValueError("duplicate/invalid LC_UNIXTHREAD")
            flavor, words = struct.unpack_from("<II", data, at + 8)
            if (flavor, words) != (6, 68):
                raise ValueError("expected ARM_THREAD_STATE64")
            entry = struct.unpack_from("<Q", data, at + 16 + 32 * 8)[0]
        elif cmd == 2:
            if length != 24 or symtab is not None:
                raise ValueError("invalid/duplicate LC_SYMTAB")
            symtab = struct.unpack_from("<4I", data, at + 8)
        elif cmd == 0xb:
            if length != 80:
                raise ValueError("invalid LC_DYSYMTAB")
            fields = struct.unpack_from("<18I", data, at + 8)
            if fields[5] or fields[15] or fields[17]:
                raise ValueError("undefined/dynamic relocations remain")
        elif cmd in (0x22, 0x80000022):
            if length != 48 or any(struct.unpack_from("<10I", data, at + 8)):
                raise ValueError("dyld opcodes must be resolved before acceptance")
        elif cmd in (0xc, 0xe, 0x18, 0x80000018, 0x8000001f, 0x80000023, 0x20,
                     0x80000028, 0x80000034, 0x80000035):
            raise ValueError("dyld dependency/LC_MAIN/chained fixups/fileset unsupported")
        elif cmd in (0x1d, 0x1e, 0x26, 0x29, 0x2e):
            if length != 16:
                raise ValueError("invalid linkedit command")
            bounded(*struct.unpack_from("<II", data, at + 8), len(data))
        elif cmd == 0x32:
            if length < 24 or length != 24 + 8 * struct.unpack_from("<I", data, at + 20)[0]:
                raise ValueError("invalid LC_BUILD_VERSION")
        elif cmd in (0x1b, 0x24, 0x25, 0x2a, 0x2b):
            if length != (24 if cmd == 0x1b else 16):
                raise ValueError("invalid version/UUID command")
        else:
            raise ValueError(f"unreviewed load command {cmd:#x}")
        at += length
    if at != end or not segments or len({s["name"] for s in segments}) != len(segments):
        raise ValueError("command total/segment names invalid")
    for key, length in (("vmaddr", "vmsize"), ("fileoff", "filesize")):
        ranges = sorted((s[key], s[key] + s[length]) for s in segments if s[length])
        if any(a[1] > b[0] for a, b in zip(ranges, ranges[1:])):
            raise ValueError("overlapping Mach-O segments")
    if not any(s["name"] == "__TEXT" and s["fileoff"] == 0 and s["filesize"] >= end for s in segments):
        raise ValueError("Mach header/commands not contained in __TEXT")
    if entry is None or entry % 4 or not any(s["initprot"] & 4 and s["vmaddr"] <= entry < s["vmaddr"] + s["filesize"] for s in segments):
        raise ValueError("entry must be aligned and inside executable file-backed bytes")
    if entry < 0xffff000000000000:
        raise ValueError("entry is outside the proposed high kernel VA range")
    if symtab is None:
        raise ValueError("unstripped LC_SYMTAB required for symbol audit")
    symoff, nsyms, stroff, strsize = symtab
    bounded(symoff, nsyms * 16, len(data))
    bounded(stroff, strsize, len(data))
    starts = []
    for i in range(nsyms):
        nameoff, typ, sect, desc, value = struct.unpack_from("<IBBHQ", data, symoff + i * 16)
        if nameoff >= strsize or b"\0" not in data[stroff + nameoff:stroff + strsize]:
            raise ValueError("invalid symbol string")
        name = data[stroff + nameoff:stroff + strsize].split(b"\0", 1)[0].decode("ascii")
        if not typ & 0xe0 and typ & 0xe == 0 and typ & 1:
            raise ValueError("undefined/common symbol: " + name)
        if not typ & 0xe0 and typ & 0xe == 0xe and not 1 <= sect <= section_count:
            raise ValueError("invalid defined-symbol section")
        if not typ & 0xe0 and typ & 1 and typ & 0xe not in (2, 0xe):
            raise ValueError("unresolved/unsupported external symbol kind")
        if name == "__start" and typ & 0xe == 0xe:
            starts.append(value)
    if starts != [entry]:
        raise ValueError("LC_UNIXTHREAD must agree with unique __start symbol")
    return {"structural_pass": True, "hardware_compatible": "UNPROVEN", "xnu_identity": "UNPROVEN",
            "sha256": hashlib.sha256(data).hexdigest(), "entry_va": entry, "segments": segments}


def mapping(report, phys_base, virt_base, mem_size, adt_pa, adt_size, args_pa, top):
    """Validate an explicit synthetic/future handoff window, never select a PA."""
    if not report.get("structural_pass"):
        raise ValueError("kernel structural audit required")
    for base, size in ((phys_base, mem_size), (virt_base, mem_size)):
        bounded(base, size, U64)
        if base % 0x4000 or size == 0 or size % 0x4000:
            raise ValueError("mapping window must have 16K alignment")
    if not phys_base < top <= phys_base + mem_size or top % 0x4000:
        raise ValueError("invalid topOfKernelData")
    ranges = []
    for s in report["segments"]:
        if s["vmsize"] and s["initprot"]:
            bounded(s["vmaddr"] - virt_base, s["vmsize"], mem_size)
            pa = phys_base + s["vmaddr"] - virt_base
            ranges.append((pa, pa + s["vmsize"]))
    for pa, size in ((adt_pa, adt_size), (args_pa, 736)):
        bounded(pa - phys_base, size, mem_size)
        if size <= 0 or pa % 8:
            raise ValueError("invalid ADT/boot_args size or alignment")
        ranges.append((pa, pa + size))
    ranges.sort()
    if any(a[1] > b[0] for a, b in zip(ranges, ranges[1:])) or ranges[-1][1] > top:
        raise ValueError("handoff overlap or allocation above topOfKernelData")
    entry_pa = phys_base + report["entry_va"] - virt_base
    return {"entry_pa": entry_pa, "deviceTreeP": virt_base + adt_pa - phys_base,
            "boot_args_pa": args_pa, "topOfKernelData": top,
            "bootstrap_tables": "UNVERIFIED; run bootstrap_coverage for upstream L2 block rounding",
            "ownership": "UNPROVEN; also run the M0.9 reservation/live-extent validator"}


def bootstrap_coverage(phys_base, virt_base, mem_size, header_pa, required, owned):
    """Model the unmodified start.s cold 16K L2 block mapping; do not build tables.

    `owned` is an explicit claim to validate separately against reservations/live
    extents. A coverage PASS does not establish that claim on physical hardware.
    """
    block = 1 << 25  # ARM_TT_L2_SHIFT for the proposed 16K granule.
    bounded(phys_base, mem_size, U64)
    bounded(virt_base, mem_size, U64)
    if not phys_base <= header_pa < phys_base + mem_size:
        raise ValueError("Mach header outside RAM window")
    delta = header_pa - phys_base
    count = (mem_size - delta) // block
    if not count or (virt_base - phys_base) % block:
        raise ValueError("zero L2 count or incongruent PA/KVA block offsets")
    start = header_pa & -block
    size = count * block
    bounded(start - owned[0], size, owned[1])
    for pa, length in required:
        if length <= 0:
            raise ValueError("empty bootstrap allocation")
        bounded(pa - start, length, size)
    return {"identity_pa_start": start, "mapped_bytes": size,
            "kva_start": (virt_base + delta) & -block,
            "warning": "rounded prefix mapped, tail omitted; ownership and table capacity remain separate gates"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.kernel.read_bytes()), indent=2))
