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
`ums512 nos_arm_asm nos_arm_pmap`. Protection feature groups, allocator metadata,
MACF and integrity policies are retained. Only KPC/kperf profiling is excluded:
the required Apple PMU source is absent and no Cortex backend exists. Apple
AMCC source files are excluded for UMS512 because that controller is absent;
generic integrity policies remain selected. No fake counter backend is used. The earlier
restricted component configuration remains available for regression checks.
Apple-specific hardware features still require porting; preserving a config
option does not prove its implementation on Cortex. This open-source desktop
profile is not the closed iOS kernel configuration. The real upstream unifdef
preprocesses its conditional groups before feature-set validation.

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
native.lock.json. Only the selected RNG/hash/HMAC C files are copied into an
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
the DRBG always uses SHA256. Cipher, AEAD and RSA capabilities remain absent;
they are not replaced with success stubs. This is a capability subset, not a
complete corecrypto replacement or FIPS-validated module. It currently supports
only the explicit MAX_CPUS=1 profile and refuses an accidental SMP build.

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
