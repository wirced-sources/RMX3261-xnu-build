"""Opt-in WSL host tools, extracted under out; no apt install or system changes.

Run --fetch once to obtain the six hash-pinned Ubuntu packages and Apple MIG
sources. Normal execution is offline. This is not an XNU macOS SDK replacement.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

from build import ROOT, tool
from xnu_sources import CACHE, verify, verify_file
from xnu_config import configure

ENV = ROOT / "out/m010-env"
HOST = ROOT / "out/m010/host"
MIG = ROOT / "out/m010-upstream/bootstrap_cmds"
LOCK = ROOT / "xnu/m010.lock.json"


def unix(path):
    path = Path(path).resolve().as_posix()
    if len(path) < 3 or path[1:3] != ":/":
        raise ValueError("expected a Windows drive path for WSL")
    return "/mnt/" + path[0].lower() + "/" + path[3:]


def run(args, **kwargs):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=60, **kwargs)
    if p.returncode:
        raise RuntimeError(f"command failed {args}:\n{p.stdout}\n{p.stderr}")
    return p


def wsl(*args):
    return run(["wsl", "-d", "Ubuntu", "--exec", *args])


def fetch():
    spec = json.loads(LOCK.read_text())
    for item in spec["xnu_files"]:
        verify_file(CACHE / "xnu" / item["path"], item)
    ENV.mkdir(parents=True, exist_ok=True)
    for item in spec["packages"]:
        target = ENV / item["file"]
        if not target.exists():
            with urllib.request.urlopen(item["url"], timeout=45) as response:
                target.write_bytes(response.read())
        if len(target.read_bytes()) != item["bytes"] or hashlib.sha256(target.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Ubuntu package hash mismatch: " + item["file"])
    if not MIG.exists():
        run(["git", "-c", "core.autocrlf=false", "clone", "--depth", "1", "--branch",
             "bootstrap_cmds-129", "https://github.com/apple-oss-distributions/bootstrap_cmds.git", MIG])


def build():
    verify()
    spec = json.loads(LOCK.read_text())
    for item in spec["xnu_files"]:
        verify_file(CACHE / "xnu" / item["path"], item)
    for item in spec["packages"]:
        p = ENV / item["file"]
        if p.stat().st_size != item["bytes"] or hashlib.sha256(p.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("host package mismatch")
        wsl("dpkg-deb", "-x", unix(p), unix(ENV / "root"))
    HOST.mkdir(parents=True, exist_ok=True)
    envroot = ENV / "root"
    binpath = unix(envroot / "usr/bin")
    local_env = ["/usr/bin/env", "M4=" + binpath + "/m4",
                 "BISON_PKGDATADIR=" + unix(envroot / "usr/share/bison")]
    source = CACHE / "xnu"
    configsrc = source / "SETUP/config"
    wsl(*local_env, binpath + "/bison", "-y", "-d", "-o", unix(HOST / "parser.c"), unix(configsrc / "parser.y"))
    wsl(*local_env, binpath + "/flex", "--header-file=" + unix(HOST / "lexer.yy.h"),
        "-o", unix(HOST / "lexer.yy.c"), unix(configsrc / "lexer.l"))
    cc = tool("clang", "CLANG")
    host_flags = ["--target=x86_64-linux-gnu", "-std=gnu17", "-DYY_NO_INPUT", "-I", str(HOST),
                  "-I", str(configsrc), "-isystem", str(envroot / "usr/include"),
                  "-isystem", str(envroot / "usr/include/x86_64-linux-gnu")]
    objects = []
    for name in ("externs", "main", "mkheaders", "mkioconf", "mkmakefile", "openp", "searchp", "parser", "lexer.yy"):
        src = (HOST if name in ("parser", "lexer.yy") else configsrc) / (name + ".c")
        obj = HOST / (name + ".o")
        run([cc, *host_flags, "-c", src, "-o", obj])
        objects.append(obj)
    # Runtime is the installed Ubuntu glibc, explicitly measured, never a target library.
    libc = subprocess.check_output(["wsl", "-d", "Ubuntu", "--exec", "cat", "/lib/x86_64-linux-gnu/libc.so.6"])
    (HOST / "libc.so.6").write_bytes(libc)
    libs = envroot / "usr/lib/x86_64-linux-gnu"
    run([tool("ld.lld", "LLD"), "-o", HOST / "config", "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2",
         libs / "crt1.o", libs / "crti.o", *objects, HOST / "libc.so.6", libs / "crtn.o"])
    config, features = configure((source / "config/MASTER").read_text(),
                                 (ROOT / "xnu/config/MASTER.arm64.ums512").read_text())
    generated = ROOT / "out/m010/generated"
    generated.mkdir(parents=True, exist_ok=True)
    confroot = ROOT / "out/m010/host-config"
    conf = confroot / "osfmk/conf"
    conf.mkdir(parents=True, exist_ok=True)
    for p in (source / "osfmk/conf").iterdir():
        if p.is_file():
            shutil.copyfile(p, conf / p.name)
    patch = ROOT / "xnu/patches-ums512/0002-non-monitor-source-selection.patch"
    patchargs = ["git", "apply", "--directory=" + confroot.relative_to(ROOT).as_posix()]
    run([*patchargs, "--check", patch], cwd=ROOT)
    run([*patchargs, patch], cwd=ROOT)
    config += f'builddir "."\nobjectdir "{unix(generated)}"\nsourcedir "{unix(source)}"\n'
    path = generated / "config.DEVELOPMENT_ARM64"
    path.write_text(config, encoding="ascii", newline="\n")
    first = wsl(unix(HOST / "config"), "-c", unix(conf), unix(path))
    if first.stderr.strip():  # This old tool can return zero despite syntax errors.
        raise ValueError("SETUP/config diagnostics: " + first.stderr)
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in generated.glob("*.h")}
    second = wsl(unix(HOST / "config"), "-c", unix(conf), unix(path))
    if second.stderr.strip() or hashes != {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in generated.glob("*.h")}:
        raise ValueError("generated configuration differs")
    if (generated / "config_pmap_ppl.h").read_text().strip() != "#define NCONFIG_PMAP_PPL 0":
        raise ValueError("unexpected PPL selection")
    makefile = (generated / "Makefile").read_text()
    for name in ("arm_init.c", "arm_vm_init.c", "start.s"):
        if "$(SOURCE_DIR)/osfmk/" not in makefile or name not in makefile:
            raise ValueError("missing UMS512 cold-init source selection: " + name)
    # Preserve an actual make dry-run, not a fabricated xcrun/SDK facade.
    make = subprocess.run(["wsl", "-d", "Ubuntu", "--exec", binpath + "/make", "-C", unix(source), "-n", "install",
                           "SDKROOT=macosx", "TARGET_CONFIGS=DEVELOPMENT ARM64 UMS512", "MAKEJOBS=-j1",
                           "OBJROOT=" + unix(ROOT / "out/m010/native-obj"),
                           "SYMROOT=" + unix(ROOT / "out/m010/native-sym"),
                           "DSTROOT=" + unix(ROOT / "out/m010/native-dst")], capture_output=True, text=True, timeout=60)
    # Probe original MIG with host libc headers; do not invent Mach SDK types.
    identity = run(["git", "-C", MIG, "rev-parse", "HEAD"]).stdout.strip()
    if identity != spec["bootstrap_cmds"]["commit"] or run(["git", "-C", MIG, "status", "--porcelain"]).stdout:
        raise ValueError("MIG source identity mismatch")
    for item in spec["bootstrap_files"]:
        verify_file(MIG / item["path"], item)
    mig = subprocess.run([cc, *host_flags, "-include", "sys/types.h", "-I", str(MIG / "migcom.tproj"),
                          "-I", str(source / "osfmk"), "-idirafter", str(source / "bsd"),
                          "-idirafter", str(source / "EXTERNAL_HEADERS"), "-fsyntax-only", str(MIG / "migcom.tproj/header.c")],
                         capture_output=True, text=True, timeout=30)
    result = {"make": wsl(binpath + "/make", "--version").stdout.splitlines()[0],
              "config_inputs": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in
                                ("xnu/config/MASTER.arm64.ums512", "xnu/patches-ums512/0002-non-monitor-source-selection.patch")},
              "config_built": True, "config_sha256": hashlib.sha256((HOST / "config").read_bytes()).hexdigest(),
              "host_libc_sha256": hashlib.sha256(libc).hexdigest(), "features": features,
              "headers": hashes, "reproducible_headers": True,
              "make_dry_run": {"exit": make.returncode, "stdout": make.stdout, "stderr": make.stderr},
              "mig_probe": {"exit": mig.returncode, "stderr": mig.stderr},
              "iig": "absent; no substitute generated code", "kernel_built": False}
    (HOST / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"SETUP/config built; {len(hashes)} headers reproducible; make exit {make.returncode}; MIG exit {mig.returncode}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    if args.fetch:
        fetch()
    build()
