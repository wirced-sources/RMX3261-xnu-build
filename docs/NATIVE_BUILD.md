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

## Verified state

Xcode15.4 in the authorized macOS CI has compiled genuine allocator builtins,
built the native host dependencies, generated XNU headers and begun target
compilation. Full kernel link and genuine arm_init execution remain separate
acceptance gates. Read STATUS.md and NOTES.md in the main local project for
exact local build and QEMU outcomes.
