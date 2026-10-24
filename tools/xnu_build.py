"""M0.9 component builds and source/ABI/patch checks. Never emits a kernel or boot image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from build import ROOT, tool
from elf import ELF
from xnu_sources import CACHE, lock, verify

PLATFORM = ROOT / "xnu/platform/ums512"
FLAGS = ["-march=armv8.2-a", "-O2", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
         "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-mgeneral-regs-only",
         "-mno-outline-atomics", "-mstrict-align", "-Wall", "-Wextra", "-Werror"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def facts(directory):
    from ums512_target import header
    board = json.loads((ROOT / "boards/ums512-hardware.json").read_text())
    (directory / "facts.h").write_text(header(board), encoding="ascii", newline="\n")


def audit_object(path, macho=False):
    data = Path(path).read_bytes()
    if not macho:
        if struct.unpack_from("<H", data, 16)[0] != 1:
            raise ValueError("expected relocatable ELF")
        e = ELF(data)
        # Data relocations are legitimate in these component objects; no executable is emitted.
        return {"format": "ELF64 AArch64 REL", "undefined": sorted(n for n, (_, sh) in e.symbols().items() if sh == 0)}
    if len(data) < 32:
        raise ValueError("truncated Mach-O")
    magic, cpu, sub, kind, ncmd, size, _, _ = struct.unpack_from("<8I", data)
    if (magic, cpu, sub, kind) != (0xfeedfacf, 0x100000c, 0, 1) or size > len(data) - 32:
        raise ValueError("expected plain arm64 MH_OBJECT, not arm64e or executable")
    at = 32
    for _ in range(ncmd):
        if at + 8 > 32 + size:
            raise ValueError("truncated Mach-O command")
        cmd, length = struct.unpack_from("<II", data, at)
        if length < 8 or length % 8 or at + length > 32 + size:
            raise ValueError("invalid Mach-O command")
        if cmd in (0x80000028, 0x80000034):
            raise ValueError("executable entry/fixups in component")
        at += length
    if at != 32 + size:
        raise ValueError("Mach-O command size mismatch")
    return {"format": "Mach-O arm64 MH_OBJECT"}


def upstream_abi(directory):
    # Read the actual ARM64 header. Only unrelated transitive debug/prototype headers are
    # suppressed by their guards; no boot declarations or field types are rewritten.
    pairs = {"revision": "Revision", "version": "Version", "virt_base": "virtBase",
             "phys_base": "physBase", "mem_size": "memSize", "top_of_kernel_data": "topOfKernelData",
             "video": "Video", "machine_type": "machineType", "device_tree": "deviceTreeP",
             "device_tree_length": "deviceTreeLength", "command_line": "CommandLine",
             "boot_flags": "bootFlags", "mem_size_actual": "memSizeActual"}
    text = '#include "platform.h"\n#define PE_CONSISTENT_DEBUG_H\n#define _PEXPERT_ARM_PROTOS_H\n'
    text += '#include <pexpert/arm64/boot.h>\n'
    for ours, theirs in pairs.items():
        text += f'_Static_assert(offsetof(struct xnu_boot_args, {ours}) == offsetof(boot_args, {theirs}), "{ours}");\n'
        text += f'_Static_assert(sizeof(((struct xnu_boot_args *)0)->{ours}) == sizeof(((boot_args *)0)->{theirs}), "{ours} width");\n'
    for ours, theirs in zip(("base", "display", "row_bytes", "width", "height", "depth"),
                           ("v_baseAddr", "v_display", "v_rowBytes", "v_width", "v_height", "v_depth")):
        text += f'_Static_assert(offsetof(struct xnu_boot_video, {ours}) == offsetof(Boot_Video, {theirs}), "{ours} video");\n'
    text += '_Static_assert(sizeof(boot_args) == sizeof(struct xnu_boot_args), "boot ABI");\n'
    text += '_Static_assert(sizeof(Boot_Video) == sizeof(struct xnu_boot_video), "video ABI");\n'
    text += '_Static_assert(_Alignof(boot_args) == _Alignof(struct xnu_boot_args), "boot alignment");\n'
    text += '_Static_assert(kBootArgsRevision2 == 2 && kBootArgsVersion2 == 2, "boot version");\n'
    # Only the two wire structures are probed here. Suppress unrelated Mach
    # prototypes by their guards, not by replacing any ADT declarations.
    text += '#define _MACH_MACH_TYPES_H_\n#define _MACH_VM_TYPES_H_\n#define __MWERKS__\n'
    text += '#include <pexpert/device_tree.h>\n'
    text += '_Static_assert(sizeof(DeviceTreeNode) == 8, "ADT node ABI");\n'
    text += '_Static_assert(sizeof(DeviceTreeNodeProperty) == 36, "ADT property ABI");\n'
    text += '_Static_assert(offsetof(DeviceTreeNodeProperty, length) == 32, "ADT length ABI");\n'
    text += '_Static_assert(_Alignof(DeviceTreeNodeProperty) == 4 && kPropNameLength == 32, "ADT alignment/name ABI");\n'
    path = directory / "upstream_abi.c"
    path.write_text(text, encoding="ascii", newline="\n")
    return path


def registration_overlay(directory):
    """Only four patched files and our header, never a copy of proprietary SDK headers."""
    target = directory / "overlay"
    patch = ROOT / "xnu/patches-ums512/0001-machine-registration.patch"
    for path in re.findall(r"^--- a/(.+)$", patch.read_text(), re.M):
        p = target / path
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(CACHE / "xnu" / path, p)
    args = ["git", "apply", "--directory=" + target.relative_to(ROOT).as_posix()]
    subprocess.run([*args, "--check", str(patch)], cwd=ROOT, check=True, capture_output=True)
    subprocess.run([*args, str(patch)], cwd=ROOT, check=True, capture_output=True)
    shutil.copyfile(PLATFORM / "UMS512.h", target / "pexpert/pexpert/arm64/UMS512.h")
    source = directory / "registration_probe.S"
    source.write_text('''/* Compile-only configuration assertion, no driver or entry point. */
#include <arm64/proc_reg.h>
#if !UMS512 || MAX_CPUS != 1 || MMU_CLINE != 6 || MMU_I_CLINE != 6
#error UMS512 registration mismatch
#endif
#if defined(CPU_HAS_APPLE_PAC) || defined(APPLE_ARM64_ARCH_FAMILY)
#error Apple CPU policy leaked into UMS512
#endif
.text
.p2align 2
''', encoding="ascii", newline="\n")
    return source, ["-DARM64_BOARD_CONFIG_UMS512", "-D__arm64__=1", "-I", str(target / "osfmk"),
                    "-I", str(target / "pexpert"), "-I", str(CACHE / "xnu/osfmk")]


def components(directory, upstream=False):
    directory = Path(directory).resolve()
    directory.relative_to((ROOT / "out").resolve())
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / "tmp"
    temporary.mkdir(exist_ok=True)
    env = dict(os.environ, TMP=str(temporary), TEMP=str(temporary), TMPDIR=str(temporary))
    facts(directory)
    sources = [(PLATFORM / p, []) for p in ("platform.c", "diag.c", "entry_regs.S", "abi.c")]
    if upstream:
        sources.append(registration_overlay(directory))
        sources += [(upstream_abi(directory), ["-I", str(CACHE / "xnu/pexpert"),
                    "-I", str(CACHE / "xnu/osfmk"), "-I", str(CACHE / "xnu/bsd")])]
        for name in ("adler32.c", "compress.c"):
            sources.append((CACHE / "xnu/libkern/zlib" / name, ["-DKERNEL=1", "-I", str(CACHE / "xnu/libkern")]))
    result = {}
    for macho, target in ((False, "aarch64-none-elf"), (True, "arm64-apple-macos11")):
        for source, extra in sources:
            key = source.stem + (".macho.o" if macho else ".elf.o")
            output = directory / key
            subprocess.run([tool("clang", "CLANG"), "--target=" + target, *FLAGS,
                            "-I", str(directory), "-I", str(PLATFORM), *extra,
                            "-c", str(source), "-o", str(output)], check=True, env=env)
            result[key] = {"bytes": output.stat().st_size, "sha256": sha(output), **audit_object(output, macho)}
    return result


def patch_check(directory):
    spec = json.loads((ROOT / "xnu/reuse.json").read_text())
    results = []
    directory = Path(directory).resolve()
    directory.relative_to((ROOT / "out").resolve())
    directory.mkdir(parents=True, exist_ok=True)
    for item in spec["patches"]:
        if item["disposition"] != "unchanged-source-candidate":
            continue
        patch = ROOT / "xnu/patches" / item["file"]
        if hashlib.sha256(patch.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != item["sha256_lf"]:
            raise ValueError("reference patch changed")
        for path in item["paths"]:
            target = directory / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(CACHE / "xnu" / path, target)
        # --directory is relative to this repository; never modify the pristine upstream cache.
        args = ["git", "apply", "--directory=" + directory.relative_to(ROOT).as_posix()]
        subprocess.run([*args, "--check", str(patch)], cwd=ROOT, check=True, capture_output=True)
        subprocess.run([*args, str(patch)], cwd=ROOT, check=True, capture_output=True)
        results.append({"id": item["id"], "apply_check": "PASS", "sha256_lf": item["sha256_lf"]})
    return results


def attempt_kernel(directory):
    # Direct make, never the reference's downloading/installing build.sh.
    args = ["make", "install", "SDKROOT=macosx", "TARGET_CONFIGS=DEVELOPMENT ARM64 UMS512",
            "BUILD_LTO=0", "BUILD_WERROR=1", "OBJROOT=" + str(directory / "obj"),
            "SYMROOT=" + str(directory / "sym"), "DSTROOT=" + str(directory / "dst")]
    try:
        p = subprocess.run(args, cwd=CACHE / "xnu", text=True, capture_output=True, timeout=45)
        result = {"exit_code": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except FileNotFoundError:
        result = {"exit_code": None, "blocker": "GNU make executable absent; compilation not entered"}
    except subprocess.TimeoutExpired:
        result = {"exit_code": None, "blocker": "make exceeded 45-second probe limit"}
    result["command"] = args
    result["tools_found"] = {t: bool(shutil.which(t)) for t in
                             ("make", "xcrun", "xcodebuild", "iig", "mig", "ctfconvert", "clang", "ld.lld")}
    result["kernel_built"] = False
    # Also enter the real upstream compiler dependency graph with available LLVM.
    source = CACHE / "xnu"
    command = [tool("clang", "CLANG"), "--target=arm64-apple-macos11", "-march=armv8.2-a",
               "-x", "assembler-with-cpp", "-DKERNEL=1", "-DARM64_BOARD_CONFIG_UMS512"]
    for include in ("osfmk", "pexpert", "EXTERNAL_HEADERS"):
        command += ["-I", str(source / include)]
    command += ["-c", str(source / "osfmk/arm64/start.s"), "-o", str(directory / "upstream_start.o")]
    probe = subprocess.run(command, text=True, capture_output=True, timeout=30)
    result["upstream_start_probe"] = {"command": command, "exit_code": probe.returncode,
                                      "stdout": probe.stdout, "stderr": probe.stderr}
    patched = command[:1] + ["-I", str(directory / "objects/overlay/osfmk"),
                             "-I", str(directory / "objects/overlay/pexpert")] + command[1:]
    probe = subprocess.run(patched, text=True, capture_output=True, timeout=30)
    result["registered_start_probe"] = {"exit_code": probe.returncode, "stderr": probe.stderr,
                                        "command": patched}
    return result


def compiler_probes(directory):
    """Reduced compiler diagnostics for 0001/0002, explicitly not XNU object builds."""
    cc = tool("clang", "CLANG")
    base = [cc, "--target=aarch64-none-elf", "-ffreestanding", "-Werror", "-fsyntax-only", "-x", "c", "-"]
    old = "typedef char aligned_byte __attribute__((aligned(8))); void f(void) { aligned_byte b[32]; (void)b; }"
    new = "void f(void) { unsigned long long b[(32+7)/8]; (void)b; }"
    samples = {"0001_original": ("void f(void) {}", ["-ftrivial-auto-var-init=zero", "-enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang"]),
               "0001_updated": ("void f(void) {}", ["-ftrivial-auto-var-init=zero"]),
               "0002_original_reduced": (old, []), "0002_updated_reduced": (new, [])}
    result = {}
    for name, (text, flags) in samples.items():
        p = subprocess.run([*base, *flags], input=text, text=True, capture_output=True)
        result[name] = {"exit_code": p.returncode, "stderr": p.stderr}
    if result["0001_updated"]["exit_code"] or result["0002_updated_reduced"]["exit_code"]:
        raise ValueError("updated compiler compatibility probe failed")
    return result


def check(out=None, require_sources=False, attempt=False):
    directory = Path(out or ROOT / "out/m09").resolve()
    directory.relative_to((ROOT / "out").resolve())
    directory.mkdir(parents=True, exist_ok=True)
    upstream = (CACHE / "xnu").exists()
    if require_sources and not upstream:
        raise ValueError("pinned source cache required; run xnu_sources.py --fetch")
    source_result = verify() if upstream else "SKIP: pinned public source cache absent"
    first = components(directory / "objects", upstream)
    second = components(directory / "repeat", upstream)
    if first != second:
        raise ValueError("component builds differ between output directories")
    patches = []
    if upstream:
        with tempfile.TemporaryDirectory(prefix="m09-patches-", dir=ROOT / "out") as temp:
            patches = patch_check(Path(temp))
    result = {"hardware_executed": False, "kernel_built": False, "boot_image_created": False,
              "source_verification": source_result, "reproducible": True,
              "objects": first, "patches": patches, "compiler_probes": compiler_probes(directory)}
    if attempt:
        if not upstream:
            raise ValueError("cannot attempt make without sources")
        result["kernel_attempt"] = attempt_kernel(directory)
        (directory / "kernel-attempt.json").write_text(json.dumps(result["kernel_attempt"], indent=2) + "\n",
                                                       encoding="utf-8", newline="\n")
    result["compiler"] = subprocess.check_output([tool("clang", "CLANG"), "--version"], text=True).splitlines()[0]
    (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"M0.9: {len(first)} component objects, reproducible; XNU kernel NOT built; hardware NOT tested")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--require-sources", action="store_true")
    p.add_argument("--attempt-kernel", action="store_true", help="record a direct make attempt without running build.sh")
    args = p.parse_args()
    check(require_sources=args.require_sources, attempt=args.attempt_kernel)
