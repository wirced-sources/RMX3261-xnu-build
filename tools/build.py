"""Offline deterministic clang/LLD build. Never calls phone tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
from elf import ELF
from logdecode import test_tag as normalize_test_tag

ROOT = Path(__file__).resolve().parents[1]


def tool(name, env):
    path = os.environ.get(env) or shutil.which(name)
    if not path:
        raise RuntimeError(f"Missing {name}; set {env} to its path")
    return path


def build(platform="ums512", uart=False, exception=False, psci=False, out=None, test_tag=None,
          return_probe=False, text_offset=0):
    if test_tag is not None: test_tag = normalize_test_tag(test_tag)
    if platform == "qemu-virt" and (uart or psci):
        raise ValueError("QEMU has its own PL011; UMS512 UART/SMC flags are invalid")
    if type(text_offset) is not int or text_offset not in (0,0x80000):
        raise ValueError("reviewed Image text offsets are 0 or 0x80000; neither selects a load PA")
    if return_probe and (platform!='ums512' or uart or exception or psci or test_tag is None):
        raise ValueError("return probe requires UMS512 RAM-only mode and an explicit identity tag")
    directory = Path(out) if out else ROOT / "out" / (platform + ("-return-probe" if return_probe else "") + ("-uart" if uart else "") + ("-exception" if exception else "") + ("-psci" if psci else ""))
    directory.mkdir(parents=True, exist_ok=True)
    # clang's preprocessor creates temporary files; keep them in the workspace.
    temporary = directory.resolve() / "tmp"
    temporary.mkdir(exist_ok=True)
    child_env = dict(os.environ, TMP=str(temporary), TEMP=str(temporary), TMPDIR=str(temporary))
    cc, ld, objcopy = tool("clang", "CLANG"), tool("ld.lld", "LD_LLD"), tool("llvm-objcopy", "LLVM_OBJCOPY")
    if platform == "ums512":
        hw = json.loads((ROOT / "boards/ums512-hardware.json").read_text())
        stdout = next(d for d in hw["devices"] if d["path"] == hw["stdout_node"])
        base = int(stdout["reg"][0]["base"], 0)
        name = "UMS512" + (" UART-OPT-IN" if uart else " RAM-ONLY")
    else:
        base, name = 0x09000000, "QEMU-VIRT TEST-ONLY"
    config = f'#define UART_BASE {base:#x}UL\n#define PLATFORM_NAME "{name}"\n'
    if test_tag is not None: config += f'#define M0_TEST_TAG "{test_tag}"\n'
    if return_probe:
        tag=bytes.fromhex(test_tag)
        config+=f'#define M0_PROBE_TAG_LO {int.from_bytes(tag[:8],"little"):#x}\n'
        config+=f'#define M0_PROBE_TAG_HI {int.from_bytes(tag[8:],"little"):#x}\n'
    (directory / "platform.h").write_text(config, encoding="ascii")
    flags = ["--target=aarch64-none-elf", "-march=armv8-a", "-O2", "-std=c11",
             "-ffreestanding", "-fpie", "-fvisibility=hidden", "-fno-stack-protector", "-fno-builtin",
             "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-mno-outline-atomics",
             "-mgeneral-regs-only", "-mstrict-align", "-Wall", "-Wextra", "-Werror",
             "-I", str(directory)]
    for active, macro in ((platform == "qemu-virt", "QEMU_VIRT"), (uart, "UMS512_UART"),
                          (exception, "EXCEPTION_TEST"), (psci, "PSCI_QUERY"),
                          (return_probe,"M0_RETURN_PROBE")):
        if active:
            flags.append("-D" + macro)
    flags.append(f'-DM0_TEXT_OFFSET={text_offset}')
    objects = []
    for source in (("start.S",) if return_probe else ("start.S", "bootstrap.c", "diag.c", "uart.c")):
        obj = directory / (Path(source).stem + ".o")
        subprocess.run([cc, *flags, "-c", str(ROOT / "shim/ums512" / source), "-o", str(obj)], check=True, env=child_env)
        ELF(obj.read_bytes()).audit_object(header=source == "start.S")
        objects.append(str(obj))
    elf_path, image = directory / "bootstrap.elf", directory / "Image"
    script=directory/'link.ld'
    subprocess.run([cc,'-E','-P','-x','c',*(['-DM0_RETURN_PROBE'] if return_probe else []),
        str(ROOT/'shim/ums512/link.ld'),'-o',str(script)],check=True,env=child_env,timeout=30)
    subprocess.run([ld, "--build-id=none", "--no-undefined", "--fatal-warnings", "-T",
                    str(script), *objects, "-o", str(elf_path)], check=True)
    e = ELF(elf_path.read_bytes())
    symbols = e.symbols()
    if e.entry != 0 or any(sh == 0 for _, sh in symbols.values()):
        raise ValueError("invalid entry or undefined symbol")
    if any(s["type"] in (4, 6, 9) and s["size"] for s in e.sections):
        raise ValueError("runtime relocation/dynamic section")
    subprocess.run([objcopy, "-O", "binary", str(elf_path), str(image)], check=True)
    size = symbols["_image_end"][0]
    data = image.read_bytes()
    if len(data) > size:
        raise ValueError("file larger than declared image")
    data += bytes(size - len(data))
    if data[56:60] != b"ARM\x64" or struct.unpack_from("<Q", data, 16)[0] != size:
        raise ValueError("bad Linux Image header")
    image.write_bytes(data)
    manifest = {"platform": platform, "uart_opt_in": uart, "exception_test": exception,
                "psci_query_opt_in": psci, "bytes": size,
                "sha256": hashlib.sha256(data).hexdigest(),
                "symbols": {n: hex(v) for n, (v, _) in symbols.items() if n in
                            ("_head", "_image_end", "m0_log", "vectors", "park", "m0_entry_snapshot")},
                "compiler": subprocess.check_output([cc, "--version"], text=True).splitlines()[0],
                "linker": subprocess.check_output([ld, "--version"], text=True).strip()}
    if test_tag is not None: manifest['test_tag'] = test_tag
    if return_probe:
        manifest.update(return_probe=True,text_offset=text_offset,record_bytes=192,
            scope='Returning M0 entry snapshot only; not XNU/launcher/recovery',
            selected_hardware_load_pa=None,hardware_approved=False)
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{platform}: {size} bytes SHA256 {manifest['sha256']}")
    return directory, manifest


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--platform", choices=("ums512", "qemu-virt"), default="ums512")
    p.add_argument("--uart", action="store_true", help="UMS512 only: inherited UART clocks/pins required")
    p.add_argument("--exception-test", action="store_true")
    p.add_argument("--psci-query", action="store_true", help="UMS512 only: optional PSCI_VERSION SMC")
    p.add_argument("--out", type=Path)
    p.add_argument('--test-tag', type=normalize_test_tag, help='optional per-test 128-bit diagnostic identity, not an entropy seed')
    p.add_argument('--return-probe',action='store_true',help='isolated returning RAM snapshot mode; not hardware authorized')
    p.add_argument('--text-offset',type=lambda x:int(x,0),default=0,help='Image offset from caller-owned 2 MiB base, not a load PA')
    a = p.parse_args()
    build(a.platform, a.uart, a.exception_test, a.psci_query, a.out, a.test_tag,a.return_probe,a.text_offset)
