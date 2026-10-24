# Native XNU build

This driver targets the pinned Apple XNU 8796.141.3 using real Xcode 15.4 on
macOS. It follows the dependency order and commands in the pinned
[darwin-xnu-build](https://github.com/blacktop/darwin-xnu-build/tree/663906528d1cd5ea8fde7de6f16de73db9511549)
and the ios-sweet workflow, applying only this project's reviewed UMS512 patches.
It does not run reference patches or import their hardware addresses, AMFI,
trust-cache, KPC, or crypto substitutes.

## Execution

```sh
# Network is explicit; every source is checked against a commit and Git tree.
python3 tools/xnu_native.py --fetch
# Xcode path is pinned in xnu/native.lock.json. No sudo or xcode-select change.
python3 tools/xnu_native.py --build
```

An offline `--prepare` works on Windows too. It creates a new isolated source
checkout under `out/native/work`; choose a fresh `--work out/native/retry` for
another preparation. Existing workspaces are never reset or deleted.

The native configuration copies upstream `config/MASTER.arm64.MacOSX`, matching
the MacOSX SDK and the profile used by ios-sweet, adding only
`ums512 nos_arm_asm nos_arm_pmap config_enforce_signed_code`. The board also
declares `options CONFIG_ENFORCE_SIGNED_CODE`: public MASTER has the attribute
name but no options declaration, so selecting the attribute alone had no effect
in native56. Real SETUP/config now emits the compiler's CONFIG_DEFINES option,
consumed by MakeInc.def. Local and CI probes preprocess the unchanged kern_cs.c
initializer to1, with an absent-option negative control of0. This strengthens
the MacOSX default to stock global process code-signing enforcement;
attachment errors must never be ignored for the lab user process. Protection feature groups, allocator metadata,
MACF and integrity policies are retained. Only KPC/kperf profiling is excluded:
the required Apple PMU source is absent and no Cortex backend exists. Apple
AMCC source files are excluded for UMS512 because that controller is absent;
generic integrity policies remain selected. No fake counter backend is used. The earlier
restricted component configuration remains available for regression checks.
Apple-specific hardware features still require porting; preserving a config
option does not prove its implementation on Cortex. This open-source desktop
profile is not the closed iOS kernel configuration. The real upstream unifdef
preprocesses its conditional groups before feature-set validation.

Native57/run40112465191 SUCCESS: original make install,37502800-byte ARM64
MH_EXECUTE,18segments,76490 validated local relocations,0imports. Kernel SHA256
4fc8d0663cbdb9c05d7e19cb3872814459577c4543581e357d928adde462281e.
Two independent boots of that exact binary confirmed global enforcement1/RO/NX,
genuine ubc_cs_blob_add return0, native cs_validate_page15/0/0, real EL0 entry,
mov x16,#20, SVC0x80/getpid/PID1 return and program success-loop. Fresh EL1
post-exec counters1/1/3/4/4 prove the controlled authorization and four actual
HFS vnode denials. Counters are never read through kernel VA while stopped in
EL0. Exact original audit/config/two traces/publication evidence are retained
under history/native57; native56's enforcement0/read failure remains archived.
This is a static owned lab program, not Apple launchd/dyld or a completed OS boot.

Before dependency builds the driver compiles and checks an ARM64 Mach-O using
the real allocator builtins. Generated headers use Apple MIG and IIG. It then
invokes upstream `make installhdrs` and `make install -k`, not a hand-picked
object list. Missing SDK/private support, compile failures and undefined symbols
remain failures. A KDK is neither downloaded nor installed. No diagnostic
`arm_init` observer is included. After make the driver audits the resulting
Mach-O with the existing strict auditor. A separate, genuine QEMU boot test
is still required. After a successful final audit, CI runs the same binary
in QEMU before the runner disappears. It never transfers that binary via
artifacts, caches, Git, releases or encoded logs. The QEMU helper requires
native source provenance, checks the in-memory arm_init bytes against the
audited file, and single-steps its real prologue. Reaching later function
boundaries is reported separately from verified subsystem operation. For the
original static-PIE kernel's local relocation table, an explicit zero-VA-slide
path validates every record's kind, width, file-backed site and already linked
pointer target. External/undefined/PC-relative/unsupported relocations still
fail. No relocation entry, code byte or protection check is removed. The loader
maps the kernel at its original virtual addresses; relocating that image to
different virtual addresses remains unsupported.

The QEMU host is built headlessly from a size/SHA256-pinned official9.2.4
source archive, with two jobs and a30-minute build bound. This avoids current
Homebrew QEMU bottles requiring newer macOS than the Xcode15.4 runner. It uses
upstream configure/Meson and the runner's GLib/Ninja where available. Guest
networking is disabled. QEMU's actual FDT supplies its RAM and GIC ranges;
CNTFRQ is read by the adapter and the guest random seed comes from host OS
entropy. These facts apply only to QEMU virt, never to the physical RMX3261.

## Export and CI boundary

```powershell
python tools/xnu_native.py --capsule
```

This produces deterministic `out/native/capsule.zip` and `capsule.json` with a
fixed, enumerated UTF-8 text allowlist and SHA256 values. It contains the driver,
source locks, reviewed patches, two Cortex policy headers and this document.
No Git history, FDT facts, private files, logs, reference checkout, SDK, source
cache, toolchain or Apple binary is exported. The workflow has read-only repo
permission, no secrets, no persisted checkout credentials, two build jobs and a
90-minute job limit. No artifact/cache upload is configured because its shared
account quota is unknown. Bounded errors and the final audit print to job logs.
Reports and any audited kernel remain in the local build workspace.
The job refuses private repositories to avoid consuming paid runner minutes.

Publication/push and dispatch require the user's explicit authorization;
`--capsule` does neither. The user subsequently authorized the independent
public repository [RMX3261-xnu-build](https://github.com/wirced-sources/RMX3261-xnu-build)
and safe updates. Every exported revision and its entire separate history are
audited before push. The main project's Git history is never published.

GitHub currently documents Xcode 15.4 on
[macos-14](https://github.com/actions/runner-images/blob/main/images/macos/macos-14-Readme.md).
That image is [scheduled to retire on November 2, 2026](https://github.com/actions/runner-images/issues/13518).
Do not silently switch to Xcode 16: ios-sweet records a different generated IORPC
ABI. PureDarwin iig-tools commit 28010c688caab7eb5400b9c98faa5b1e538e0108 is
rejected: it uses FNV-1a message IDs and ignores trailing Clang flags, so it cannot
be mixed with Apple's generated DriverKit interfaces.

## Historical native build progress before the portable provider

Xcode15.4 in the authorized macOS CI has compiled genuine allocator builtins,
built the native host dependencies, generated XNU headers and LINKED/AUDITED
the full ARM64 MH_EXECUTE (19636296 bytes, zero unresolved imports). QEMU9.2.4
is built on the same ephemeral runner. Run39678485260 also completed upstream
make install and executed genuine arm_init instructions in QEMU. After the
physmap fix, run39682365345 observed genuine returns from pmap_bootstrap,
arm_vm_init, zone_bootstrap, vm_mem_bootstrap, sched_init and ipc_init, reaching
kernel_bootstrap and then a progress-UI assertion in PE_init_iokit. The headless
QEMU profile uses the original UI-only -noprogress boot argument. Runs39684378294
and39686543379 passed that UI assertion and repeated all six initializer returns.
The latter localized a real data abort at _kmem_crypto_init+0x24 (x0=0), called
by _kernel_startup_initialize_upto+0xb4. The source requires a registered crypto
provider before this EARLY_BOOT callback; none has been supplied. A fake RNG
or bypass is not an acceptable substitute. These are completed early initializer
paths, not a completed OS boot or working iOS.
Both independent native builds produced identical19636296-byte kernels with
SHA2566629790e7644510fb78871359d82b4df9151571e973c63d736a5ef03e5b667bb
using upstream ZERO_AR_DATE. Reproducibility across other environments is untested.
The run20 panic decoder incorrectly packed two uint32 variadic arguments into one
slot: Darwin uses eight-byte slots. PC/LR and the first registers are unaffected;
ESR is recoverable as0x96000005, but FAR was outside its320-byte read. The local
decoder now reads336 bytes and three64-bit slots; its next native CI execution
is deliberately pending because the user requested saving and stopping.
The board uses full16KB L1 (47-bit VA) to cover the
stock MacOSX ARM_LARGE_MEMORY link address; subpage L1 only covers39 bits.
Unavailable Apple-only PMU/IOMMU interfaces are removed from explicit export
lists rather than supplied by fake implementations. Read STATUS.md and NOTES.md
in the main local project for exact build and QEMU outcomes.

The local `python tools/physmap_bounds.py` regression extracts the exact pinned
XNU arm_vm_physmap_slide function and exercises all65536 page-aligned1GB slides
with the audited QEMU image layout. Page-table writes are recorded by a host-test
hook; this checks bounds arithmetic only. The original non-PPL ARM_LARGE_MEMORY
aperture omits alignment gaps. The UMS512 patch reserves up to one twig per PTOV
entry in both the aperture bound and its L1 allocation, preserving the assertion
and page protections. The QEMU ADT includes an empty /defaults node so pmap uses
its own default ASID count, without inventing hardware limits.

## Portable crypto integration

Run39767993309 verified the old failure exactly: PC0xfffffe0007b97060,
instruction0xf940a908 (LDR X8,[X8,#0x150]), X8=0, FAR0x150, ESR0x96000005
(read translation fault at level1). g_crypto_funcs and crypto_init were both0;
register_crypto_functions was never entered before kmem_crypto_init. Thus the
callback table is absent. Instruction bytes match the audited kernel. A QEMU
XML namespace issue prevented the optional page-table walk; that inspector is
corrected separately. No page-table walk result is inferred from the failure.

The new platform adapter uses the SHA256 HMAC_DRBG implementation from the
[official BearSSL0.6 release](https://www.bearssl.org/), pinned by size/SHA256 in
native.lock.json. Initially selected RNG/hash/HMAC C files are copied into an
isolated build tree, retaining the MIT notices. No Apple corecrypto implementation
is redistributed. Its original interfaces and registration order were examined.

The startup callback runs at EARLY_BOOT/FIRST, before kmem_crypto_init at MIDDLE.
It registers the genuine XNU PRNG callbacks and crypto table. The master consumes
XNU's existing conditioned bootloader seed, rejects short/uninitialized input,
mixes the nonce and domain, and uses a mutex. Fresh entropy comes through XNU's
original health-tested entropy_provide callback; errors are fatal. No timestamp
or fixed test seed is used as live entropy. Contexts for private KMEM RNGs are
160 bytes and generate without locks, allocation or global RNG calls. Uniform
values use rejection sampling. Each generation request is bounded to64KiB and
the2^48 request limit is enforced, including after untrusted reseed input.

The adapter also supplies actual MD5/SHA1/SHA256/SHA384/SHA512 and HMAC functions
with the original context ABI, constant-time tag comparison, and non-destructive
digest finalization. Legacy hash algorithms remain for existing ABI consumers;
the DRBG always uses SHA256. In this historical initial provider, cipher, AEAD and RSA capabilities remain absent;
they are not replaced with success stubs. This is a capability subset, not a
complete corecrypto replacement or FIPS-validated module. It currently supports
only the explicit MAX_CPUS=1 profile and refuses an accidental SMP build.

Current capability additions and exact validation are tracked in
[AES_CBC.md](AES_CBC.md): real ct64 CBC and typed hash-vtable ABI thunks;
native execution is recorded separately from host KATs.

The native build executes tests/crypto_rng_kat.c using the actual portable adapter
before compiling XNU. The kernel startup itself additionally checks all five
digest known answers, RFC4231 HMAC generation/verification and a negative tag,
and the [NIST HMAC_DRBG worked example](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_DRBG.pdf)
before publishing any callbacks. Passing these tests is not a security audit of
the new adapter or proof of later kernel runtime. Live seeds/DRBG states are
never printed by the debugger inspection.

Run39773199088 subsequently BUILT/LINKED/AUDITED the19682696-byte full kernel
(SHA256d6c556d7a418fe23b70dbf4387c22af38506d64a2eed4521d70aa53dcf772c08)
and observed genuine returns from provider startup, register_and_init_prng,
kmem_crypto_init and both commpage initializers. The mandatory crypto tests
therefore passed inside XNU. Its next stop is the original Image4 guard in
trust_cache_runtime_init. Read-only-late lockdown has not yet been reached.
No Image4/AMFI success substitutes or signing policy changes are included.

The optional real-kernel API test requires `ums512-selftest=1` and exact QEMU ADT
model matching. It runs after the original enabling of IRQs and MAC policy setup,
before the unchanged Image4 guard. It checks eight wired allocation/free cycles
with zero-fill and data verification, plus private kernel-port message queue
roundtrips using the normal send/receive/destruction paths. A small public-count
record is read by the debugger; no message-signature checks are skipped.
Run39777726707 completed the hook:8 allocation/free cycles,851968 bytes verified,
4 private ports and8 actual kernel message roundtrips. Its IRQ-enabled phase
and actual function return were confirmed. It then hit the unchanged Image4
guard, with img4if=0 and amfi=0. This does not verify userspace IPC, blocking
between threads, scheduler switching or interrupt delivery. The next independent
build39780973901 completed two fresh-entropy QEMU boots with identical passing
VM/IPC counters and the same Image4 guard. Its19683072-byte unstripped Mach-O
is bit-identical to independent build39777726707:
SHA2562d883d9aedeb556c7d969ee050fd8b2ab165330e02bcde96a921eee0b8bdb860.
Different bootstrap stack VAs show runtime ASLR differed. Arbitrary GPRs,
unrecognized panic argument blocks and unused stack slots are not exported.

## Experimental trust verifier and interrupt backend

The current security integration adds a real Image4 v9 ABI subset around the
same verifier: private payload/manifest snapshots, ownership/deallocation,
firmware evaluate/execute error propagation and an explicit laboratory chip.
Only bare `trst` objects are supported. Nonces, vnode evaluation, other flags,
custom/Apple chip environments and newer Image4 features are unsupported and
cannot authenticate. This is not an implementation of all AppleImage4 v18.

The TrustCache v3 ABI adapter supports authenticated owned module snapshots,
UUID duplicate checks, registry-validated query tokens and all v3 accessors.
Only private type0x80 is accepted; this is NOT an Apple platform trust category.
Raw modules, Apple static/engineering/legacy caches and nonce-personalized types
are denied. Registry operations use an actual XNU mutex. Modules are bounded,
non-unloadable and checked for post-load corruption before queries.

Before publishing the real interfaces, an early mandatory MAC policy registers
an execution quarantine: code-signature attachment, exec, executable mmap,
anonymous executable mappings, executable mprotect, invalid-code exceptions and
code-signing flag changes are denied. Data mappings retain their ordinary policy.
This deliberately blocks ALL userspace execution pending CodeDirectory/CMS/page
integration; a valid lab manifest does not grant code execution. Entitlement
queries deny privileges, CoreEntitlements version0 advertises no interpreter.
No production AMFI compatibility, entitlements or Apple boot trust are claimed.
The stock trust_cache_runtime_init and subsequent startup calls remain intact.
Run39807654638 subsequently linked/audited the19836584-byte genuine kernel,
SHA256e56496e8ad28fd61823344f5fb672fc67d2c84ef03d72435f1ba46c58b9f45f9,
18segments/72191 validated local relocations/0 imports. Two fresh boots returned
from stock trust_cache_runtime_init, all firmware/cache/query tests and static
cache loading, then entered bsd_init. Actual PL011 ID/clock/divisor/ready marker
and3835 transmitted bytes were verified per boot. The next stock panic is
IOPanicPlatform::start: no matching QEMU platform driver. BSD is not complete.
The individual lockdown boundary symbols were not observed (LTO); reaching BSD
implies their stock order, while direct post-lockdown RO/NX checks are pending.

The follow-up QEMU Platform Expert adds an exact-model catalogue personality
while retaining IOPanicPlatform for unknown platforms. It creates actual IOKit
MMIO descriptors/nubs for FDT-derived GIC, UART and RTC ranges. Its PL031 backend
maps the real virtual peripheral, checks all eight ID bytes, masks/clears RTC
interrupts and requires the1Hz counter to advance within a bounded wait. Calendar
reads use the device register; writes use its load register with a32-bit bound.
This is a seconds-resolution emulated clock, not a trusted anti-rollback clock.
The implementation follows [QEMU9.2.4 PL031](https://github.com/qemu/qemu/blob/v9.2.4/hw/rtc/pl031.c).
CPU-on, IOMMU, power and storage are unsupported. Native compilation/execution
of this new Platform Expert are pending; the local C++ probe requires the real
native exported SDK/header context and is not replaced with header facades.

Run39812929454 subsequently linked and executed that Platform Expert twice:
its real start/configure returned, three nubs/four MMIO ranges were published,
PL031 ID and counter advance passed. Both security pointer/table VA mappings
were measured read-only/NX after stock lockdown. Execution then waited before
an observed bsd_autoconf; no panic. Stock IOKitInitializeTime waits for resource
IORTC, which the initial backend had not published. The follow-up provides a
real typed IORTC subclass delegating reads/writes to that verified PL031, and
publishes readiness only after a successful calendar read. Alarm/power requests
remain explicit unsupported failures. Added time/buffer/BSD trace boundaries.

The trace also checks restored entry SP before accepting a function return and
does not install return breakpoints for the two nonreturning bootstrap routines.
A shared Call_continuation PC in the initial trace belonged to another thread;
it is not evidence that kernel_bootstrap_thread completed.

Run39816207000 then returned from original IOKitInitializeTime and vfsinit in
both fresh trials. The typed IORTC service thus satisfies the required resource
contract; no panic followed. Before BSD autoconfiguration, mcache_init calls
ml_wait_max_cpus. ARM waits for platform completion of CPU enumeration, which
the initial platform had not published. The follow-up checks actual QEMU FDT
and XNU read-only parsed topology against the executing MPIDR and machine_info,
then calls the real ml_set_max_cpus. It neither changes machine_info nor creates
a CPU/interrupt-controller facade. Only the current single CPU is supported;
this is not SMP/PSCI CPU-on. The next native trace observes that publication,
actual mcache/mbuf paths and later BSD stages.

Run39818436348 returned from ml_set_max_cpus, ml_wait_max_cpus, mcache_init,
IOMapperIOVMAlloc, mbinit and audit_init in both fresh boots. Its next original
panic is pthread_shims.c:318: the pthread kernel function table is NULL.
The matching Apple release manifest provides libpthread514.100.2. The follow-up
statically compiles its real kern_init/kern_support/kern_synch units and invokes
the original pthread_start/pthread_kext_register before the unchanged pthread_init.
This adds source to the kernel build, not a dynamically loaded unsigned kext.
All signing/MAC guards remain. Four module-private names are isolated from core
XNU; original kext header context is used only for those units. A real ABI mismatch
is addressed explicitly: libpthread's ARM64 ksyn_waitq_element is56 bytes/aligned8,
whereas this open XNU's opaque storage was48/aligned1. For this board the whole
uthread layout is rebuilt with the exact56-byte/aligned8 pointer-bearing record,
preserving typed allocator pointer metadata; both real provider and native storage
compile-time assert the same size/alignment. No function-table substitute or
fake initializer is provided. Full native compilation/execution is pending.

The first native pthread integration attempt39822447955 failed in the four new
units because raw OSFMK header roots captured standalone string.h/types.h, and
the bridge lacked prerequisite kernel/BSD type includes. No Mach-O passed audit
and QEMU was explicitly NOT RUN. The correction gives only the three provider
units priority to the freshly exported and genuine SDK Kernel.framework headers
and SDK usr/include, using upstream per-object CFLAGS_ADD. No SDK/header facade
or type/warning-check removal is used. The bridge follows native shim include
order. Subsequent workflow attempts compile XNU before preparing the QEMU host.

Run39825365247 compiled the bridge and its native wait-record ABI assertions.
Only the three provider units remained: pointer/integer conversions at current
callback boundaries, obsolete panic redeclaration, SDK user-zlib/kernel crc32
collision and two implicit narrowing conversions. The installer applies exact
reviewed source corrections: full-width address casts, integer zero user-address
sentinels, bounded QoS/state conversion, and the genuine noreturn panic header.
The pinned XNU libkern include root selects its namespaced kernel zlib before
the SDK's user zlib. All warnings/type checks stay enabled. No kernel was linked
and no QEMU execution occurred for that failed attempt.

Run39827200491 removed those conversion/prototype errors, leaving a mixed
public/private framework header diagnostic, user-zlib CRC collision, and one
remaining integer user-address NULL. The next attempt restores the normal
native XNU export roots for provider private types. Its prefix includes the
actual SDK string.h by absolute verified SDK path and the actual namespaced XNU
libkern/zlib.h before later includes. Prerequisite native type headers are explicit;
no framework-privacy warning is disabled and no substitute header is generated.
The remaining user-address sentinel is integer zero. Fresh preparation verifies
all exact source edits before CI publication.

Run39829296012 rejected the SDK libc prefix because its dependent libc headers
are absent from native kernel include roots. The next correction uses the
original XNU string.h BSD sys/types.h branch instead: MACH_KERNEL_PRIVATE is
restored immediately after that include, while XNU_KERNEL_PRIVATE stays1.
Compile-time guards require XNU's actual fortify header. Real exported kext
headers provide opaque private API types; native Mach architecture exports
precede SDK framework fallbacks, preventing mixed framework leaf headers.
No warning, fortify, allocator or security option is disabled.

Run39805659988 acquired its runner and passed allocator/compiler, crypto/verifier
and generated-header/dependency gates. Full kernel compilation stopped at the
Image4 log forwarder: -Wformat-nonliteral required its own printf-style attribute.
The callback now declares __printflike(4,5); the warning is retained. No native
kernel/boot was produced by that attempt. Full raw diagnostics remain ignored.

The additional QEMU PL011 console backend is included inside the stock pe_serial
multiplexer. Its MMIO range and fixed uartclk are validated from the actual QEMU
FDT and exported as bounded ADT properties; no Realme UART constants are used.
The backend checks all eight PrimeCell identity bytes against the ARM PL011
implemented by [QEMU9.2.4](https://github.com/qemu/qemu/blob/v9.2.4/hw/char/pl011.c),
computes 115200-baud divisors, disables UART DMA/interrupts and provides polled
TX/RX. A bounded real TX marker and public counters distinguish execution from
compilation. `serial=1` uses the original console route. Raw serial output stays
ephemeral/ignored; only the fixed readiness marker and counters are reported.
The complete patched pe_serial.c compiles locally with actual XNU ARM64 headers.
Local QEMU11.1.0's actual FDT validates at0x09000000/4096 bytes/24MHz; this is
separate from the pending native QEMU9.2.4 execution and no physical I/O claim.

Run39802629382 never acquired a runner: job119907241053 has no steps or runner
name. GitHub's annotation explicitly reports hosted-runner acquisition failure
and macOS arm64 capacity constraints. This is not a compiler/kernel failure.
GitHub has [announced](https://github.blog/changelog/2026-10-01-github-actions-macos-14-runner-image-retirement/)
reduced macos-14 capacity and retirement on2026-11-02. No paid runner is used.

The added libDER/libDERImg4 subset is pinned to OpenCore
25d02c8d051dc2e9d9166b5a3b343ec5b77104cc and fetched with size/SHA256 verification.
Its APSL2/BSD notices are retained in the isolated tree. Platform headers,
alignment-safe descriptor stores and const-correct decoder views are adapted;
internal functions are made static or declared explicitly. BearSSL RSA public
verification has explicit bounded narrowing conversions and a hash/OID length
guard. Upstream signature, certificate-role and payload checks remain enabled.
No UEFI digest override or physical platform identity is imported.

The strict `trst` IM4M laboratory profile uses a synthetic QEMU identity, pinned
public root/issuer/leaf certificates and real RSA2048/SHA256. It verifies raw v2
SHA256 CDHash modules without privilege flags. It has positive, negative and
mutation/truncation tests. It neither registers Image4/AMFI tables nor replaces
their MAC/entitlement/runtime semantics. `tests/security_abi.c` also compiles the
original interfaces directly. Native compilation and actual kernel tests remain
distinct from the host tests; source documentation describes the missing policy.

The QEMU-only GICv3 backend uses FDT-derived ADT ranges, checks distributor DS=1
and affinity routing, selects the redistributor by full MPIDR affinity, configures
Group1NS PPI27 and registers an actual XNU interrupt handler. It acknowledges
IAR1 and completes EOI1 after the original rtclock_intr returns. No secure-state
transition is attempted. It refuses a physical/unknown model or security state.
The optional kernel hook queues three original timer_call deadlines and requires
their callbacks in real masked interrupt context before timeout. This path still
requires execution evidence; compilation alone does not verify IRQ delivery.
The handler compiles in OSFMK because its timer dispatch uses private CPU state;
PExpert invokes its initializer without exposing private headers. The optional
test also sends a targeted Group1 SGI to the current CPU, then starts a genuine
kernel thread and exchanges four semaphore handshakes. An empty semaphore wait
must expire through the original timer/scheduler path. These are opt-in tests,
not a replacement scheduler or an SMP implementation. The lab trust backend
also performs authenticated CDHash queries, with unknown/unauthenticated inputs
rejected; it still grants no execution rights or entitlements.

Run39790947172 subsequently completed upstream make install, strict audit and
two fresh genuine kernel executions. Kernel19807288 bytes/SHA256
41e34f27e437effdf59b4809fd79036d23e29ad32ce289724e99ee931d9aa2e9,
18 segments,72112 validated local relocations,0 undefined imports. Real arm_init
at0xfffffe0007bb6758 and actual hook return were observed. Both boots passed33
trust checks,8 wired allocations/832KiB and8 kernel IPC roundtrips,9 timer IRQ
entries/rtclock returns,3 timer_call callbacks,1 self-SGI,4 worker semaphore
handshakes and a timed-out empty wait. The termination flag is set before the
last worker reply; it is not proof of thread reaping. The last stock startup
function remains trust_cache_runtime_init, then the original Image4 panic with
img4if=amfi=0. Independent build39793380415 completed with the exact same
19807288-byte unstripped kernel/SHA256, without binary normalization. Its two
fresh boots repeated all checks, so four boots across two independent full
builds passed. Timer IRQ counts were9/9/10/8 (asynchronous timing varies), with
three requested callbacks, one self-SGI and four semaphore exchanges each.
Native30 also verified the actual QEMU FDT timer binding before loading the
kernel. All new runtime evidence is separate from historical cold diagnostics.


## 2026-10-22 — genuine libpthread initializer returned; TCP crypto dependency

- Native42/run39831699626/job120009220749 completed SUCCESS, all actual job steps
  succeeded. Original make install + strict Mach-O audit: 19892200 bytes,18segments,
 72907 validated local relocations,0imports,
  SHA256177fd8463a2228bcc13487d7983fab41390a9324676d8aa8fae0eec9cc6be6e7. Genuine arm_init0xfffffe0007bc3328 executed in both boots.
- Both passed original trust_cache_runtime_init,42/30/25/7 security checks, live
  RO/NX security pointers/tables and targeted VM/IPC/IRQ/timer/thread/platform/
  RTC/UP enumeration checks. Native36 proofs archived under docs/history/native36.
- Trial1 stopped at unchanged interrupt-mask timing watchdog after audit_init;
  exact timing variadic args not yet decoded. Trial2 returned real registration,
  actual Apple _pthread_init and dlil_init, entered domaininit, then data abort
  tcp_init+0x158 PC0xfffffe0007733c6c/LR0xfffffe0007733c60/SP0xfffffe787569f7c0,
  ESR0x96000005/FAR0. Audited instruction0xf9400008 = LDR X8,[X0], X0=0;
  effective address matches FAR and VA0 has no valid mapping.
- Pinned source chain is tcp_tfo_init -> aes_encrypt_key128 -> aes_encrypt_key,
  which loads g_crypto_funcs->ccaes_cbc_encrypt->size. Provider is registered
  (_crypto_init1; g_crypto_funcs0xfffffe000723b830), pointer mapped RO/NX; CBC
  field currently NULL. Required cipher is CBC, not an ECB descriptor. No cipher
  fallback/stub, TFO disable or security-check bypass was introduced.
- Real libpthread locks/hash/thread-call initializer returned in one trial;
  this does not establish working userspace psynch/syscalls or complete BSD.
  No root mount/network traffic/SMP/iOS/physical UMS512 verification. Phone untouched.


## 2026-10-22 — real AES CBC fixes TCP; root discovery entered twice

- Native43/run39837482280/job120029495186 completed SUCCESS: original full
  make install/strict audit, 19915936 bytes,18segments,72926
  validated local relocations,0imports,SHA2566e61a41d181c9a86af807ff26ced7715badf276225f435ce3280ce35018fce34.
  Real arm_init0xfffffe0007bc7024 executed twice, SP0xfffffe0007d0c000,
  BootArgs0xfffffe00083e8000; no observer. Native42 proofs archived separately.
- Both boots returned real AES selftest/crypto startup (including original XNU
  wrapper KAT), stock trust runtime and42/30/25/7 security checks, pthread
  registration/_pthread_init, dlil_init, tcp_init, domaininit, skywalk_init and
  sysctl_mib_init. Both entered IOFindBSDRoot0xfffffe0007b5529c and did not return
  during bounded observation. No panic/data abort/watchdog in either new boot.
- Both registered actual CBC descriptors: encrypt0xfffffe000723b830,
  decrypt0xfffffe000723b858, context264bytes/block16. Early table sampling was
  before lockdown (crypto pointer still writable then); no late crypto page
  protection claim is inferred. Security Image4/AMFI pointers/tables were live
  measured RO/NX after lockdown. Targeted VM/IPC/IRQ/timer/thread/RTC/UP checks pass.
- No root storage/IOMedia/filesystem integrated. Exact internal root resource/
  media wait has not yet been read. Idle sample is another thread, not BSD stack.
  Original source performs IOBSD wait then media selection. No root mount,
  filesystem I/O, packet traffic, userspace psynch/execution, SMP or iOS claimed.
- Native43 total98 stops reached root discovery:96 startup cap did not truncate
  this run. The earlier15sec RSP silent interval stopped idle observation before
  the overall45sec deadline. Next harness uses full remaining deadline and
  exports only known static root matching booleans. No timeout/protection in
  the kernel was changed. Timing panic native42 remains historical/open.
- Independent socket selftest and tracer refinements are implemented/prepared,
  not target-tested. Complete local check.py91unit+8offlineQEMU PASS. Phone untouched.


## 2026-10-22 — genuine BSD sockets and exact root-media boundary verified twice

- Native45/run39841638879/job120043909921 completed SUCCESS, original make
  install/strict Mach-O audit: 19916480 bytes,18segments,72926 validated local
  relocations,0imports, SHA25695a666ac5eab62e7d33b323125f92c1b14b033808f566e532e07b247b0de13c3. Real arm_init0xfffffe0007bc7664
  executed twice. Native43 audit/executions preserved in docs/history/native43.
- Both boots repeat stock trust runtime and42firmware/30cache/25query/7policy
  checks, targeted VM/IPC/GIC/timer/thread/RTC/UP tests, real AES/pthread/TCP/
  domain/Skywalk/sysctl initialization. Actual AF_LOCAL stream and datagram
  operations passed:2pairs/12messages/1180bytes,4 EWOULDBLOCK empty receives,
  1 genuine stream EOF. No replacement socket services or userspace code.
- Both returned loopattach and inittodr; entered IOFindBSDRoot0xfffffe0007b558dc.
  Bounded static console markers now prove !BSD timeout then Waiting on matching
  IOMedia/Apple_HFS. This is the original root selection with no root disk/image,
  storage family or HFS backend integrated. No panic/fault in either45sec window;
  no root mount/complete BSD/iOS. No blocked BSD stack unwind claim.
- A late Platform Expert start return is a different IOService thread; the last
  directly observed BSD initializer return remains inittodr. Live page walks
  at root entry now prove g_crypto_funcs pointer, actual crypto table and both
  CBC descriptors RO/NX; security pointer/table RO/NX checks also passed.
- Source implementation remains unchanged after the verified export23863e5;
  only evidence/docs updated. Native44 one-error failure and all old proofs are
  retained. Final local check.py91unit+8QEMU PASS; all-hash HMAC/AES/RNG host
  fatal ASan/UBSan PASS; IM4M33+4509 rejection regression PASS. Physical phone
  untouched. Source preparation/remaining genuine HFS/storage/authentication
  work is explicit, not presented as an unavailable universal closed component.

## 2026-10-23: genuine HFS/storage kernel and actual root-selection assertion

The root build now pins IOStorageFamily-302.140.2 and hfs-627.100.6 from the
same macos-135 source manifest. tools/xnu_storage.py installs original kernel
units and creates an owned16MiB HFS+ image using hdiutil inside the isolated
runner workspace. Raw image geometry/metadata is checked, then image bytes and
the per-build SHA256 pin are embedded as read-only kernel data. No phone image,
Apple userland, host disk, SDK export or artifact/cache upload is involved.
Filesystem formatting metadata means image/kernel hashes vary across builds;
each exact image pin belongs to its own kernel, rather than a reproduction claim.

Native51/run39954278824/job120416102179 passed original make install and strict
Mach-O audit:37411912 bytes,18segments,75834 checked local relocations,0imports,
SHA256d255666b1ec3bafebdd8c01f5f7eb8e300311e9240cd90106091189421621a3a.
Actual arm_init0xfffffe0008c4872c executed. Real HFS registration returned;
VM/IPC/security/AF_LOCAL tests passed. IOFindBSDRoot reached the stock
IOService::setRootMedia assertion requiring IOBlockStorageDriver's real class.
No mounted root/file I/O/userspace is claimed for that run. Native52 therefore
adds the genuine kernel-provider driver implementation, keeping the assertion.
DriverKit's separate userspace provider is unavailable and not impersonated.

CONFIG_PROTECT, MAC and code-signing checks remain enabled. The actual SDK lacks
AppleKeyStoreFSServices.h, and the public HFS tree lacks key-roll source and a
private generation flag. Internal requests use genuine XNU key-buffer types;
missing file-key operations and every protected-volume mount fail ENXIO.
No private ABI/constant/key is guessed. Root authentication verifies the actual
immutable image SHA256 and exact BSD device/root/read-only state. This explicit
QEMU trust domain is not Apple's APFS sealed root. Execution quarantine remains.

New tests require genuine mounted HFS vnode read/EOF/EROFS/ENOENT/nonroot-auth
operations, not just service publication. Both boot trials run even on failure;
the workflow still fails if either fails. Assertion/abort evidence takes priority
over secondary incomplete-counter errors. Root profile observation is bounded
at90sec; guest timers/watchdog unchanged. See ROOT_STORAGE.md and the preserved
docs/history/native51 audit/one trace. Older verified runtime45 remains separate.

Native52/run39959208305 completed full make install and strict audit, then both
real boots mounted HFS root. Kernel37499816B/18segments/76488local relocations/
0imports, SHA f7d4a951b0374daa04bdd78e2928b07b4c48eff06ce3ab180acbae78573e3e61.
Real vfs_mountroot/auth/devfs/bsd_utaskbootstrap/bsd_init returned; vnode read47B,
EOF/EROFS/ENOENT/nonroot-auth tests passed. The first init exec reached real
load_init_program and failed ENOENT for absent /sbin/launchd. This is mounted
root and completed bsd_init, not user execution or completed OS boot. Exact
two traces/audit are current and retained in history/native52; native45 archived.

The next image contains only an owned, deliberately unsigned trap-only ARM64
init asset. A real Apple compiler/linker build is checked for plain MH_EXECUTE,
file-backed trap entry and absent signature/dyld imports. Real init exec must
reach mandatory MAC quarantine and fail EAUTH80; direct early callback selftests
cannot satisfy the new counters. All security checks and execution quarantine
remain unchanged. No Apple binary/key or external disk input is used.

Native53/run39963215637/job120446257979 passed full original make install,
strict audit and both actual boots. Full kernel37499904B,18segments,
76488local relocations,0imports; SHAddbb2a57d15826b110702542c50f616edbd83cad3c61a7f47c425b7f4af68d44.
Real arm_init0xfffffe0008c53980 executed. Both boots again mounted/authenticated
HFS root, passed vnode/block/VM/IPC/security/IRQ/thread/RTC/socket tests and
returned from devfs_kernel_mount, bsd_utaskbootstrap and bsd_init. Existing
owned unsigned /sbin/launchd reached actual PID1 MAC exec callback exactly
once and was denied EAUTH80; stock init-failure panic remains intact.
No positive Mach-O user activation, code-page validation or EL0 execution.
Current exact audit/two traces are retained in history/native53; native52's
two genuine HFS mount/ENOENT traces are preserved separately. Different image
formatting metadata means these are two successful root builds, not bit-identical
kernel reproduction. Local97unit+8M0QEMU PASS; current/historical physmap controls PASS.
