"""Native Apple build, using the upstream Makefiles and Xcode 15.4.

--fetch downloads pinned Apple OSS sources. --prepare is offline and portable.
--build requires macOS/Xcode; never installs a KDK, changes xcode-select, exports
an SDK, runs a diagnostic observer, or supplies allocator/crypto/CS success stubs.
--capsule exports a fixed text-only allowlist, without publishing anything.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import struct
import subprocess
import time
import zipfile

from xnu_config import configure

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out/native"
PATCHES = (
    "xnu/patches-ums512/0001-machine-registration.patch",
    "xnu/patches-ums512/0002-non-monitor-source-selection.patch",
    "xnu/patches-ums512/0003-panic-region-offset.patch",
    "xnu/patches-ums512/0004-cortex-cold-entry.patch",
    "xnu/patches-ums512/0005-exclude-apple-iommu.patch",
    "xnu/patches-ums512/0006-pmap-build-context.patch",
    "xnu/patches-ums512/0007-cortex-source-selection.patch",
    "xnu/patches-ums512/0008-vnode-argument-offset.patch",
    "xnu/patches-ums512/0009-portable-lp64-build-fixes.patch",
    "xnu/patches-ums512/0010-native-portability.patch",
    "xnu/patches-ums512/0011-native-arm64-integration.patch",
    "xnu/patches-ums512/0012-unused-uart-registration.patch",
    "xnu/patches-ums512/0013-native-link-dependencies.patch",
    "xnu/patches-ums512/0014-isolate-lldb-syntax-checker.patch",
    "xnu/patches-ums512/0015-remove-unavailable-pmu-exports.patch",
    "xnu/patches-ums512/0016-remove-unavailable-apple-iommu-exports.patch",
    "xnu/patches-ums512/0017-reserve-physmap-alignment-slack.patch",
    "xnu/patches-ums512/0018-qemu-kernel-api-validation.patch",
    "xnu/patches/0005-non-pac-build-fixes.patch",
)
CAPSULE = (
    "tools/crypto_check.py", "tests/crypto_rng_kat.c",
    "tools/xnu_crypto.py", "xnu/platform/ums512/ums512_rng.h",
    "xnu/platform/ums512/ums512_rng.c", "xnu/platform/ums512/ums512_crypto.c",
    "xnu/platform/ums512/ums512_runtime.c",
    "tools/xnu_native.py", "tools/xnu_config.py", "tools/macho_kernel.py", "tools/xnu_kernel_qemu.py", "tools/fdt.py", "tools/qemu_host.py", "xnu/native.lock.json",
    "xnu/sources.lock.json", "xnu/platform/ums512/UMS512.h",
    "xnu/platform/ums512/cpu_entry.h", "ci/xnu-native.yml",
    "docs/NATIVE_BUILD.md", *PATCHES,
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def specs():
    lock = json.loads((ROOT / "xnu/native.lock.json").read_text())
    sources = dict(lock["sources"])
    sources["xnu"] = json.loads((ROOT / "xnu/sources.lock.json").read_text())["xnu"]
    return lock, sources


def output(*args, cwd=None):
    return subprocess.check_output([str(a) for a in args], cwd=cwd, text=True, timeout=180).strip()


def verify_source(path, spec):
    for ref, expected in (("HEAD", spec["commit"]), ("HEAD^{tree}", spec["tree"])):
        if output("git", "-C", path, "rev-parse", ref) != expected:
            raise ValueError("source identity mismatch: " + str(path))
    if output("git", "-C", path, "status", "--porcelain"):
        raise ValueError("source cache is not pristine: " + str(path))


def source(name):
    _, sources = specs()
    candidates = [OUT / "cache" / name]
    if name == "xnu":
        candidates.append(ROOT / "out/m09-upstream/xnu")
    elif name == "bootstrap_cmds":
        candidates.append(ROOT / "out/m010-upstream/bootstrap_cmds")
    for path in candidates:
        if path.exists():
            verify_source(path, sources[name])
            return path
    raise FileNotFoundError("pinned source absent, use --fetch: " + name)


def fetch():
    from xnu_crypto import archive
    archive(fetch=True)
    _, sources = specs()
    for name, spec in sources.items():
        try:
            source(name)
            continue
        except FileNotFoundError:
            pass
        path = OUT / "cache" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        output("git", "-c", "core.autocrlf=false", "clone", "--depth", "1", "--branch",
               spec["tag"], spec["repository"] + ".git", path)
        verify_source(path, spec)


def full_master(text):
    """Preserve protection features; exclude unsupported Apple PMU profiling."""
    pattern = r"^(#\s+KERNEL_BASE\s*=\s*\[)([^\]]+)(\])"
    text, count = re.subn(pattern, r"\1\2 ums512 nos_arm_asm nos_arm_pmap \3", text, flags=re.M)
    if count != 1:
        raise ValueError("upstream MASTER group changed")
    pattern = r"^(#\s+PERF_DBG_BASE\s*=\s*\[)([^\]]+)(\])"
    def without_apple_pmu(match):
        words = match[2].split()
        if words.count("kpc") != 1 or words.count("kperf") != 1:
            raise ValueError("upstream PMU feature group changed")
        return match[1] + " " + " ".join(w for w in words if w not in ("kpc", "kperf")) + " " + match[3]
    text, count = re.subn(pattern, without_apple_pmu, text, flags=re.M)
    if count != 1:
        raise ValueError("upstream PMU group missing")
    return text + "\noptions UMS512 # <ums512>\n"


def master_for_validation(text):
    # Match upstream doconf's UMS512 (non-virtual SoC) preprocessing. Use the
    # real unifdef, not a partial conditional parser that can drop policy groups.
    command = (["/usr/bin/xcrun", "unifdef"] if platform.system() == "Darwin" else
               ["wsl", "-d", "Ubuntu", "--exec", "/usr/bin/unifdef"])
    result = subprocess.run([*command, "-t", "-USOC_IS_VIRTUALIZED", "-USOC_CONFIG_t8020"],
                            input=text.encode(), capture_output=True, timeout=30)
    if result.returncode not in (0, 1) or result.stderr.strip():
        raise RuntimeError("upstream MASTER preprocessing failed")
    return result.stdout.decode()


def clone_work(name, work):
    dest = work / name
    if dest.exists():
        raise ValueError("refusing to overwrite build sources; choose a fresh --work: " + str(dest))
    output("git", "-c", "core.autocrlf=false", "clone", "--shared", "--no-checkout", source(name), dest)
    output("git", "-C", dest, "config", "core.autocrlf", "false")
    output("git", "-C", dest, "config", "core.eol", "lf")
    output("git", "-C", dest, "-c", "core.autocrlf=false", "checkout", "--detach", specs()[1][name]["commit"])
    verify_source(dest, specs()[1][name])
    return dest


def prepare(work):
    work = Path(work).resolve()
    work.relative_to((ROOT / "out").resolve())
    work.mkdir(parents=True, exist_ok=True)
    src = clone_work("xnu", work)
    for patch in PATCHES:
        output("git", "-C", src, "apply", "--check", ROOT / patch)
        output("git", "-C", src, "apply", ROOT / patch)
    from xnu_crypto import install as install_crypto
    install_crypto(src)
    shutil.copyfile(ROOT / "xnu/platform/ums512/UMS512.h", src / "pexpert/pexpert/arm64/UMS512.h")
    (src / "osfmk/ums512").mkdir()
    shutil.copyfile(ROOT / "xnu/platform/ums512/cpu_entry.h", src / "osfmk/ums512/cpu_entry.h")
    shutil.copyfile(ROOT / 'xnu/platform/ums512/ums512_runtime.c',src / 'osfmk/ums512/ums512_runtime.c')
    with (src/'osfmk/conf/files').open('a',newline='\n') as config_stream:
        config_stream.write('\nosfmk/ums512/ums512_runtime.c\toptional ums512\n')
    master = (src / "config/MASTER").read_text()
    original = (src / "config/MASTER.arm64.MacOSX").read_text()
    board = full_master(original)
    _, before = configure(master, master_for_validation(original))
    _, after = configure(master, master_for_validation(board))
    if (set(after) - set(before) != {"ums512", "nos_arm_asm", "nos_arm_pmap"}
            or set(before) - set(after) != {"kpc", "kperf"}):
        raise ValueError("native board unexpectedly changed upstream features")
    (src / "config/MASTER.arm64.ums512.MacOSX").write_text(board, encoding="utf-8", newline="\n")
    result = {"source_commit": specs()[1]["xnu"]["commit"], "security_features_preserved": True,
              "excluded_unsupported_apple_pmu": ["kpc", "kperf"],
              "upstream_master": "MASTER.arm64.MacOSX", "sdk_profile": "MacOSX",
              "features": after, "patches": {p: digest(ROOT / p) for p in PATCHES},
              "portable_crypto": specs()[0]['portable_crypto'],
              "crypto_adapters": {n: digest(ROOT / 'xnu/platform/ums512' / n)
                                  for n in ('ums512_rng.h','ums512_rng.c','ums512_crypto.c')},
              "diagnostic_observer_included": False, "kernel_linked": False, "arm_init_executed": False}
    (work / "prepared.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("PREPARED: full ARM64 configuration; protection features preserved; unsupported KPC/kperf excluded", flush=True)
    return src


def rewrite(path, old, new, count=1):
    text = path.read_text()
    if text.count(old) != count:
        raise ValueError("upstream build integration changed: " + str(path))
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def run(args, name, report, env, cwd, timeout=1800):
    """Bound each process group and log; never print environment variables."""
    logfile = report / (name + ".log")
    print("BUILD: " + name, flush=True)
    start = time.monotonic()
    with logfile.open("wb") as log:
        proc = subprocess.Popen([str(a) for a in args], cwd=cwd, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        while proc.poll() is None:
            if time.monotonic() - start > timeout or log.tell() > 128 * 1024 * 1024 or shutil.disk_usage(cwd).free < 8 * 1024**3:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                raise RuntimeError("process budget exceeded: " + name)
            time.sleep(1)
    if proc.returncode:
        lines = logfile.read_text(errors="replace").splitlines()
        missing = sorted(set(re.findall(r'^\s*"([^"\n]+)", referenced from:', "\n".join(lines), re.M)))
        if missing:
            (report / (name + "-undefined.json")).write_text(json.dumps(missing, indent=2) + "\n")
            print("UNRESOLVED SYMBOLS: " + str(len(missing)), flush=True)
            print("\n".join(missing[:500]), flush=True)
        failures = [line for line in lines if re.search(r"make(?:\[[0-9]+\])?: \*\*\*.*Error [0-9]+",line)]
        if failures:
            print('FAILED MAKE TARGETS:\n'+'\n'.join(dict.fromkeys(failures))[:10000],flush=True)
        # Recursive make may continue installing headers long after a compiler
        # failure. Export bounded ERROR CONTEXT, not just that unrelated tail.
        indices = set()
        families = {}
        sites = {}
        for i, line in enumerate(lines):
            # Downstream make failures are not separate compiler root causes.
            if re.search(r"make(?:\[[0-9]+\])?: \*\*\*.*Error [0-9]+", line):
                continue
            if re.search(r"(?i)(?:fatal error:|\berror:|\bError [0-9]|exported name not in import list|No rule to make|Undefined symbols|^ld:|not found|No such file|SyntaxError|ImportError|ModuleNotFoundError)", line):
                warning = re.search(r"\[-W[^]]+\]", line)
                key = warning[0] if warning else re.sub(r"'[^']*'|`[^']*'|\b[0-9]+\b", "<value>", line.split("error:")[-1])
                count, sample = families.get(key, (0, line))
                families[key] = (count + 1, sample)
                sites.setdefault(line, None)
                if count < 3:
                    indices.update(range(max(0, i - 2), min(len(lines), i + 7)))
        print("DIAGNOSTIC FAMILIES: " + str(len(families)) + " (at most120 shown)", flush=True)
        for count, sample in list(families.values())[:120]:
            print(str(count) + " occurrences: " + sample[:1000], flush=True)
        # A family can occur in many independent files (e.g. LP64 casts).
        # Include their actual locations so later failures are not concealed
        # by the three-contexts-per-warning budget.
        print("DIAGNOSTIC SITES: " + str(len(sites)) + " (at most250 shown)", flush=True)
        for site in list(sites)[:250]:
            print(site[:1200], flush=True)
        selected = sorted(indices)[:700]
        if not selected:
            selected = list(range(max(0, len(lines) - 35), len(lines)))
        print("\n".join(lines[i][:1600] for i in selected), flush=True)
        print('FINAL BUILD LOG TAIL:\n'+'\n'.join(lines[-35:])[:14000],flush=True)
        raise RuntimeError(f"{name} exit {proc.returncode}; see {logfile}")


def build(work):
    if platform.system() != "Darwin":
        raise RuntimeError("native build needs macOS and real Xcode; no xcrun/SDK facade is used")
    lock, _ = specs()
    env = os.environ.copy()
    env["DEVELOPER_DIR"] = lock["host"]["developer_dir"]
    # Upstream newvers.pl explicitly supports reproducible date/object-root
    # overrides. Use the verified source commit's timestamp, not wall-clock time.
    epoch = output("git", "-C", source("xnu"), "show", "-s", "--format=%ct", "HEAD")
    env["SOURCE_DATE_EPOCH"] = epoch
    env["ZERO_AR_DATE"] = "1" # Upstream ld64: zero N_OSO debug-map timestamps.
    env["KERNEL_BUILD_DATE"] = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).isoformat()
    env["KERNEL_BUILD_OBJROOT"] = "xnu-8796.141.3/DEVELOPMENT_ARM64_UMS512"
    version = subprocess.check_output(["/usr/bin/xcodebuild", "-version"], env=env, text=True, timeout=30).strip()
    if not version.startswith("Xcode " + lock["host"]["xcode"] + "\n"):
        raise ValueError("requires pinned Xcode 15.4 for the 8796 IORPC ABI: " + version)
    env["PATH"] = env["DEVELOPER_DIR"] + "/Toolchains/XcodeDefault.xctoolchain/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    work = Path(work).resolve()
    work.relative_to((ROOT / "out").resolve())
    work.mkdir(parents=True, exist_ok=True)
    # Upstream syntax_checker.py uses /usr/bin/env python. Supply a real local
    # Python3 alias, without changing the system interpreter or skipping checks.
    bindir = work / "bin"
    bindir.mkdir(exist_ok=True)
    # /usr/bin/python3 is an Xcode tool-dispatch shim: invoking its symlink as
    # "python" makes it search for the removed tool with that basename.
    # Resolve the actual Xcode interpreter before creating the local alias.
    python3 = output("/usr/bin/xcrun", "--find", "python3")
    (bindir / "python").symlink_to(python3)
    env["PATH"] = str(bindir) + ":" + env["PATH"]
    report = OUT / "report"
    report.mkdir(parents=True, exist_ok=True)
    sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], env=env, text=True, timeout=30).strip()
    tools = {n: subprocess.check_output(["xcrun", "--find", n], env=env, text=True, timeout=30).strip()
             for n in ("clang", "clang++", "ld", "iig")}
    probe = work / "allocator-compiler.c"
    probe.write_text('''#if !__has_builtin(__builtin_xnu_type_summary) || !__has_builtin(__builtin_xnu_type_signature) || !__has_builtin(__builtin_xnu_types_compatible)
#error Real XNU allocator type builtins are required
#endif
struct data { unsigned long a, b; };
struct pointers { void *a, *b; };
_Static_assert((__builtin_xnu_type_summary(struct data) & 0xffff) == 4, "data granules");
_Static_assert((__builtin_xnu_type_summary(struct pointers) & 0xffff) == 2, "pointer granules");
_Static_assert(__builtin_xnu_types_compatible(struct data, struct data), "same type");
const char *data_signature = __builtin_xnu_type_signature(struct data);
const char *pointer_signature = __builtin_xnu_type_signature(struct pointers);
''', encoding="utf-8")
    run([tools["clang"], "-arch", "arm64", "-ffreestanding", "-Werror", "-c", probe, "-o", work / "allocator-compiler.o"],
        "allocator-compiler", report, env, work, 60)
    if struct.unpack_from("<4I", (work / "allocator-compiler.o").read_bytes()) != (0xfeedfacf, 0x100000c, 0, 1):
        raise ValueError("compiler did not produce plain ARM64 Mach-O")
    (report / "toolchain.json").write_text(json.dumps({"xcode": version, "sdk": sdk, "tools": tools,
        "allocator_builtins_compiled": True}, indent=2) + "\n")
    src = prepare(work)
    run([python3,ROOT/'tools/crypto_check.py',src/'libkern/ums512','--compiler',tools['clang']],
        'crypto-known-answer',report,env,work,120)
    deps = {name: clone_work(name, work) for name in lock["sources"]}
    fake = work / "fakeroot"
    fake.mkdir()
    rewrite(deps["bootstrap_cmds"] / "xcodescripts/install-mig.sh", "-o root -g wheel", "", count=2)
    rewrite(deps["Libsystem"] / "Libsystem.xcconfig", '#include "<DEVELOPER_DIR>/Makefiles/CoreOS/Xcode/BSD.xcconfig"', "")
    rewrite(src / "libsyscall/Libsyscall.xcconfig", '#include "<DEVELOPER_DIR>/Makefiles/CoreOS/Xcode/BSD.xcconfig"', "")
    # Use the open, matching AvailabilityVersions generator as in DXB. This
    # changes a build-tool path only; no target declaration is substituted.
    alias = src / "bsd/sys/make_symbol_aliasing.sh"
    rewrite(alias, 'AVAILABILITY_PL="${SDKROOT}/${DRIVERKITROOT}', 'AVAILABILITY_PL="${FAKEROOT_DIR}')
    common = ["SDKROOT=macosx", "TARGET_CONFIGS=DEVELOPMENT ARM64 UMS512", "ARCH_CONFIGS=ARM64",
              "DSTROOT=" + str(fake), "FAKEROOT_DIR=" + str(fake), "KERNEL_BUILDS_IN_PARALLEL=1",
              "MEMORY_SIZE=" + output("/usr/sbin/sysctl", "-n", "hw.memsize"),
              "SYSCTL_HW_PHYSICALCPU=2", "SYSCTL_HW_LOGICALCPU=2"]
    def xbuild(name, action, extra):
        archs = "arm64 x86_64" if name in ("bootstrap_cmds", "dtrace") else "arm64"
        run(["xcodebuild", action, "-sdk", "macosx", "-jobs", "2", "ARCHS=" + archs, "VALID_ARCHS=" + archs,
             "CODE_SIGN_IDENTITY=-", "DSTROOT=" + str(fake), "OBJROOT=" + str(work / (name + ".obj")),
             "SYMROOT=" + str(work / (name + ".sym")), *extra], name, report, env, deps[name])
    env["LD"] = tools["clang"]
    env["LDPLUSPLUS"] = tools["clang++"]
    xbuild("bootstrap_cmds", "install", ["-project", "mig.xcodeproj", "RC_ProjectNameAndSourceVersion=bootstrap_cmds-129"])
    xbuild("dtrace", "install", ["-target", "ctfconvert", "-target", "ctfdump", "-target", "ctfmerge"])
    run(["make", "install", "-j2", "DSTROOT=" + str(fake)], "AvailabilityVersions", report, env, deps["AvailabilityVersions"])
    # All paths stay inside the isolated work tree; SDK and /Library untouched.
    mig = next(fake.rglob("mig"))
    migcom = next(fake.rglob("migcom"))
    ctf = {n: str(next(fake.rglob(n))) for n in ("ctfconvert", "ctfmerge", "ctfdump")}
    native = [*common, "MIG=" + str(mig), "MIGCOM=" + str(migcom), *[n.upper() + "=" + p for n, p in ctf.items()],
              "SRCROOT=" + str(src), "OBJROOT=" + str(work / "xnu.obj"), "SYMROOT=" + str(work / "xnu.sym"),
              "INCFLAGS_SDK=-I" + str(fake / "usr/local/include/kernel"),
              "LDFLAGS_KERNEL_SDK=-L" + str(fake / "usr/local/lib/kernel") + " -L" + sdk + "/usr/local/lib/kernel",
              # Newer Clang reports intentionally dead debug/statistics locals.
              # Keep the warning visible; no blanket BUILD_WERROR=0 or check removal.
              "RC_NONARCH_CFLAGS=-Wno-error=unused-but-set-variable",
              # Keep future-proof ICMP size guards and their diagnostics. The
              # current fixed protocol header is smaller than either mbuf bound.
              "icmp6.o_CWARNFLAGS_ADD=-Wno-address-of-packed-member -Wno-error=tautological-value-range-compare",
              # PF_KEY keeps its allocation/encoded-length assertions even
              # where the current constant key-size limits prove them true.
              "key.o_CWARNFLAGS_ADD=-Wno-error=tautological-value-range-compare",
              # zalloc's bounds check covers every current two-bit heap ID.
              # Skywalk logging compares non-error flag combinations against
              # its error sentinel. Retain those checks and visible warnings.
              *[name + ".o_CWARNFLAGS_ADD=-Wno-error=tautological-value-range-compare"
                for name in ("zalloc", "nx_monitor", "nx_netif", "nexus_adapter")],
              # In 8796, BUILD_JSON_COMPILATION_DATABASE=1 REPLACES compiling
              # with command generation. It must not be set for a real build.
              "CONCISE=0", "VERBOSE=NO"]
    run(["make", "installhdrs", "-j2", *native], "xnu-headers", report, env, src)
    xbuild("Libsystem", "installhdrs", ["FAKEROOT_DIR=" + str(fake)])
    run(["xcodebuild", "installhdrs", "-sdk", "macosx", "-jobs", "2", "ARCHS=arm64", "VALID_ARCHS=arm64",
         "TARGET_CONFIGS=DEVELOPMENT ARM64 UMS512", "DSTROOT=" + str(fake), "FAKEROOT_DIR=" + str(fake),
         "OBJROOT=" + str(work / "libsyscall.obj"), "SYMROOT=" + str(work / "libsyscall.sym")],
        "libsyscall-headers", report, env, src / "libsyscall")
    for folder in ("include", "private"):
        shutil.copytree(deps["libplatform"] / folder, fake / "usr/local/include", dirs_exist_ok=True)
    firehose = deps["libdispatch"] / "xcodeconfig/libfirehose_kernel.xcconfig"
    rewrite(firehose, "$(SDKROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders",
            "$(FAKEROOT_DIR)/System/Library/Frameworks/Kernel.framework/PrivateHeaders")
    rewrite(firehose, "$(SDKROOT)/usr/local/include", "$(FAKEROOT_DIR)/usr/local/include", count=2)
    xbuild("libdispatch", "install", ["-target", "libfirehose_kernel", "FAKEROOT_DIR=" + str(fake)])
    (fake / "usr/local/lib/kernel/liblibfirehose_kernel.a").rename(fake / "usr/local/lib/kernel/libfirehose_kernel.a")
    # Keep-going collects real errors across components; failures stay failures.
    make_error = None
    try:
        run(["make", "install", "-k", "-j2", *native], "xnu-kernel", report, env, src, 2700)
    except RuntimeError as error:
        make_error = error
    finally:
        objects = {}
        formats = {"Mach-O arm64 MH_OBJECT": 0, "LLVM bitcode (architecture not independently audited)": 0}
        target = work / "xnu.obj/DEVELOPMENT_ARM64_UMS512"
        for path in [*target.rglob("*.o"), *target.rglob("*.cpo")]:
            with path.open("rb") as stream:
                header = stream.read(16)
            if len(header) == 16 and struct.unpack("<4I", header) == (0xfeedfacf, 0x100000c, 0, 1):
                kind = "Mach-O arm64 MH_OBJECT"
            elif header[:4] in (b"BC\xc0\xde", b"\xde\xc0\x17\x0b"):
                kind = "LLVM bitcode (architecture not independently audited)"
            else:
                continue
            objects[path.relative_to(target).as_posix()] = {"sha256": digest(path), "format": kind}
            formats[kind] += 1
        core = {n: h for n, h in objects.items() if Path(n).stem in (
            "arm_init", "arm_vm_init", "pmap", "vm_map", "vm_fault", "vm_page", "kalloc", "zalloc",
            "ipc_kmsg", "mach_msg", "device_tree", "OSObject", "IOService")}
        inventory = {"object_formats": formats, "core_objects": core,
                     "scope": "compiled object inventory; final link status is recorded by the subsequent Mach-O audit",
                     "arm_init_executed": False}
        (report / "object-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
        print(json.dumps(inventory, indent=2), flush=True)
    from macho_kernel import audit
    kernels = list((work / "xnu.obj").rglob("kernel.development.ums512.unstripped"))
    if not kernels and make_error:
        raise make_error
    if len(kernels) != 1:
        raise ValueError("expected exactly one upstream linked kernel")
    data = kernels[0].read_bytes()
    print(json.dumps({"native_link_candidate_sha256": digest(kernels[0]), "bytes": len(data),
                      "mach_header": list(struct.unpack_from("<8I", data))}), flush=True)
    result = audit(data, zero_slide_local_relocations=True)
    result.update(kernel_linked=True, arm_init_executed=False, hardware_verified=False,
                  source_commit=specs()[1]["xnu"]["commit"], diagnostic_observer_included=False,
                  upstream_install_succeeded=make_error is None)
    (report / "kernel-audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    shutil.copyfile(kernels[0], report / "kernel.development.ums512.macho")
    print("LINKED AND AUDITED; actual arm_init/QEMU execution remains unverified", flush=True)
    if make_error:
        raise make_error


def capsule():
    target = OUT / "capsule.zip"
    target.parent.mkdir(parents=True, exist_ok=True)
    manifest = {}
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in CAPSULE:
            path = ROOT / name
            if path.is_symlink() or path.resolve() != path.absolute() or path.stat().st_size > 512 * 1024:
                raise ValueError("unsafe capsule input: " + name)
            data = path.read_bytes().replace(b"\r\n", b"\n")
            data.decode("utf-8")
            if b"\x00" in data:
                raise ValueError("binary capsule input: " + name)
            dest = ".github/workflows/xnu-native.yml" if name == "ci/xnu-native.yml" else name
            info = zipfile.ZipInfo(dest, date_time=(2023, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
            manifest[dest] = hashlib.sha256(data).hexdigest()
        ignore = b"/out/\n__pycache__/\n"
        info = zipfile.ZipInfo(".gitignore", date_time=(2023, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, ignore)
        manifest[".gitignore"] = hashlib.sha256(ignore).hexdigest()
    record = {"archive": "out/native/capsule.zip", "sha256": digest(target), "files": manifest,
              "private_inputs": False, "published": False}
    (OUT / "capsule.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--capsule", action="store_true")
    parser.add_argument("--work", type=Path, default=OUT / "work")
    args = parser.parse_args()
    if args.fetch:
        fetch()
    if args.prepare:
        prepare(args.work)
    if args.build:
        build(args.work)
    if args.capsule:
        capsule()
