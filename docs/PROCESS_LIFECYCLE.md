# Owned ARM64 process lifecycle on genuine XNU

Native61/run40122405101 passed full Apple make install/audit and two independent
QEMU boots of one real kernel, implementation11e81ad from native57/fa92bd8.
Kernel SHA256 efd1fa07756968946d584d7cf89a804ca1a47ab2719e58532e307b05b37f5bef.
Exact audit, owned-image metadata and both original runtime JSON traces are in
history/native61; the assertions below passed in both boots.

PID1 init and PID2 child completed real HFS I/O, private NX mmap/CoW, fork,
three execve attempts (two EAUTH80, one authenticated), inherited pipe, child
exit37, parent wait4/status0x2500, ECHILD and munmap. Native fork/execve/exit/
wait4 handlers were observed; both images entered EL0 and executed their first
instructions and getpid. Last native return: getpid → unix_syscall+0x33c at
0xfffffe0008a7e6ec; final parent EL0 PC0x100003ec4, x0=0x515. PID1 stays alive.

| Observation | Boot1 | Boot2 |
|---|---|---|
| Init code entry | 0x100003c80 | 0x100003c80 |
| Child code entry | 0x110003ea0 | 0x110003ea0 |
| Parent VM table root, ASID removed | 0x441c4000 | 0x44184000 |
| Fork child VM table root, ASID removed | 0x441a0000 | 0x44198000 |
| Executed child VM table root, ASID removed | 0x44464000 | 0x4445c000 |
| Parent private PA at VA0x10000c000, value0x111 | 0x44408000 | 0x44404000 |
| Child private PA at same VA, value0x222 | 0x44414000 | 0x44410000 |

Both code mappings were RO/user-executable and private data NX. Stock global
code signing enforcement was1/RO/NX. Two different vnodes each received genuine
ubc_cs_blob_add return0 and cs_validate_page validated15/tainted0/nx0 on the
executed page; the vnode authorizer additionally verified every signed slot.
Fresh post-exec EL1 counters were exec2/signature2/files6/denials6/vnode-tests4.
The four early vnode checks rejected unsigned/altered-page/damaged-CMS/foreign-
valid-chain assets; two later actual child execve calls rejected unsigned and
altered child files. These are not measured post-mapping invalid-page kills.

Native58 was cancelled for SP preflight; native59 had a watchdog panic in one
boot and first-open timeout in the other. Missing board __ARM_PAN_AVAILABLE__
had compiled stock user_access_enable/disable away. The corrected feature gate
uses the genuine PAN0 user-copy window and restores PAN1; boot verifies MMFR1.
Native60's icount experiment hung after kernel_bootstrap; native61 uses the
original native57 QEMU time model. All stock protection/watchdog checks remain.
Separate pinned-QEMU clock/PAN fixture passes; full XNU icount is unverified.
Exact failed audits/traces remain in history/native58/59/60. No kernel process
callbacks, debugger guest-state writes or policy bypasses were introduced.

Pinned Apple source: XNU8796.141.3, commit
1b191cb58250d0705d8a51287127505aa4bc0789. The syscall table in
bsd/kern/syscalls.master defines exit1,fork2,read3,write4,open5,close6,wait4-7,
getpid20,pipe42,execve59,munmap73,mmap197. ARM64 unix_syscall and
arm_prepare_syscall_return in bsd/dev/arm/systemcalls.c use x16/SVC0x80,
x0/x1 results and carry for errno. No Linux syscall numbers or ABI are assumed.

bsd/kern/kern_fork.c:571 calls fork1(PROC_CREATE_FORK), cloneproc with
CLONEPROC_FLAGS_INHERIT_MEMORY and thread_dup. osfmk/arm64/status.c:2026 sets
the child's x0=child PID,x1=1; parent receives child PID,x1=0. The child can run
before the parent returns. Both branches are observed without scheduling-order
assumptions. Native VM inheritance gives private CoW mappings, not a shared task.
posix_spawn is a separate real path (kern_exec.c:3377), with the third argument
described by sys/spawn_internal.h:_posix_spawn_args_desc. This iteration uses
fork/execve so that VM inheritance/CoW can also be measured; it does not fake or
advertise a userspace spawn library. No vfork/shared-address-space shortcut.

execve enters kern_exec.c:4880 and the existing real Mach-O activation, MAC
authorization, signature attachment and VM signed-page validation path.
sys_pipe.c:392 allocates real descriptors and returns read/write fds in x0/x1.
kern_exit.c:2825 implements wait4; the parent requires the same child PID and
status37<<8, then ECHILD on a second wait. Child exit is syscall1, not a kernel
test callback. mmap/munmap use sys/mman.h PROT_READ|PROT_WRITE, MAP_PRIVATE|
MAP_ANON,16KiB; no executable data mappings or entitlement exceptions.

The two freestanding assembly programs in xnu/userspace have no libc, dyld or
Apple code. Each has a distinct CodeDirectory identifier/digest and independent
detached CMS signature under the same isolated per-build pinned root/leaf.
The second image is not a copy of the signed init. Independent signatures do
not imply an additional Apple/production trust domain. Only the two exact lab
identifiers are accepted; all former signature/entitlement restrictions remain.

Init opens/reads/compares47 owned HFS bytes, tests EOF, closes and requires EBADF.
It maps private NX data, writes0x111, creates a pipe and forks. The child writes
0x222 at the inherited VA; the observer must measure a different physical page
and TTBR0 root. In that actual child context, execve of unsigned-child and
altered-child must return EAUTH. A valid separately signed lab-child then loads.
The pipe write fd is inherited through exec and passed as a bounded argv string.
Child verifies distinct getpid and getppid1, reads HFS again, writes its PID and
result to the real pipe, closes it and exits37. Parent waits, verifies its own
sentinel still0x111, reads the child result/EOF, closes, requires ECHILD, unmaps
and confirms its final getpid1. Init remains alive in a final success-loop only
after the lifecycle completes; exiting PID1 would intentionally panic XNU.

Read-only host observation uses symbols from the actual owned linked Mach-O
files. Entry instructions must actually retire in EL0; user code must be RO/X,
private data NX. No debugger memory/register writes, guest callback shortcuts,
pre-exec counter fallback or mocked process execution. The native kernel must
report two distinct attachment vnodes, both validated by cs_validate_page,
global enforcement1/RO/NX, complete prior runtime gates and actual lifecycle
syscall handler entries. All former negative vnode trust tests remain.

Local results before native58: both actual Mach-O assets built; genuine CMS/CD
backend ASan/UBSan accepts both and rejects unsigned/altered/CMS/foreign assets.
check.py103unit+8offlineM0QEMU PASS. These are not runtime lifecycle evidence.
One local assembler error (unencodable cmp immediate0x2500) was fixed using a
register comparison before any full CI build. Native57 exact evidence is retained.
The first dispatched native58 was cancelled before accepting a runtime result:
preflight found the stock static entry stack is8 modulo16, while SCTLR.SA0 is
enabled. Both owned entry stubs now align SP before SP-based memory access;
child argc/argv use the saved original pointer. The observer also requires
aligned SP after startup. SCTLR alignment protection remains unchanged.

After confirmation, stop this iteration. The next separately authorized scope
should resolve the pinned dyld startup ABI/LC_LOAD_DYLINKER, a minimal open-source
libsyscall/libSystem dependency graph, initial stack/aux/argv/TLS/errno and Mach
bootstrap needs. The current signature profile explicitly denies dyld commands
and executable file mmap: extending those requires authenticated vnode/CD
binding plus native page enforcement for every loader/library and negative
tests, never a broad executable-mmap exception. Start with owned signed
loader/library fixtures before testing an open-source dyld build. No Apple IPSW,
private shared cache, production entitlements or closed iOS components are inputs.
