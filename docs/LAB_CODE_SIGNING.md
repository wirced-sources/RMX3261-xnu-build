# Isolated QEMU executable authorization

Native57 confirmed enforced signed EL0/getpid twice; see history/native57.
The next process-lifecycle implementation is locally built/checked, awaiting
native58 runtime evidence. Native57 remains the last confirmed native baseline.

The files are our own static ARM64 Mach-O init and child. Their first instructions
issue Darwin getpid20 via SVC0x80. The lifecycle programs use native fd I/O,
fork/execve/exit/wait4 and private NX mmap; see PROCESS_LIFECYCLE.md. They contain
no Apple launchd, dyld, library dependency or entitlement. Each is signed
independently with a distinct CodeDirectory/CMS under the same controlled leaf.
Real compiler/linker output is extended with LC_CODE_SIGNATURE and a standard
embedded-signature SuperBlob. CodeDirectory0x20100 uses SHA256 and16KiB slots,
HARD|KILL, no special slots/team/platform flag, one of the two exact laboratory
identifiers org.rmx.qemu.init/org.rmx.qemu.child and
full prefix coverage. Each signature includes a detached standard CMS SignedData.

The intentionally narrow [RFC5652 CMS](https://www.rfc-editor.org/rfc/rfc5652)
profile has one RSA2048/SHA256 signer, issuerAndSerialNumber, id-data and no
signed attributes or attached content. Unsupported algorithms, attributes,
multiple signers, extra certificates and trailing data fail closed. This uses
the standard detached no-attribute form supported by
[OpenSSL CMS](https://docs.openssl.org/3.5/man1/openssl-cms/), not a new signature
container. The allowed digest/algorithm is fixed, not negotiated from input.
The signature authenticates the exact CodeDirectory bytes; page hashes bind the
entire executable prefix, including header/load commands and padding.

Each build creates a new isolated root CA and leaf with genuine OpenSSL3 OS
entropy. Root CA has critical CA/pathlen0/keyCertSign/cRLSign; the leaf has
critical CAfalse/digitalSignature/codeSigning EKU. Both exact public DER
certificates are compiled as the approved pins. Private temporary key files
exist only inside ignored build work and are deleted in finally before kernel
compilation; no keys or PEM are printed/uploaded. These are laboratory keys,
not personal credentials, Apple keys or GitHub secrets. Per-build pins mean an
executable from a different build is not trusted by the next kernel.

Runtime checks perform real RSA verification of root self-signature, root→leaf
certificate signature and CMS signature. Certificate SPKI, issuer/subject,
signer serial and validity interval are parsed and checked. Exact DER pins bind
the known approved critical constraints; this is not a general X.509 extension
or delegation engine. Only UTC years2000..2049 are supported. Calendar time is
the QEMU PL031-derived XNU clock; it is not a tamper-resistant trusted wall clock
or production anti-rollback mechanism. Unsupported profiles cannot fall back
to success. Existing Image4 fixture root/caches remain unchanged and confer
no Apple platform privilege on this new signing chain.

`ums512_lab_authorize_vnode` reads real regular-file bytes only from readonly
HFS. Whole-file verification checks CMS, CodeDirectory and every signed page.
Immutable root data avoids a write race between permission and use; every
mutable/other filesystem is denied. The MAC exec callback permits only files
passing this operation. The signature callback additionally compares genuine
cs_blob CD digest/bytes, bounds, base offset and absent entitlement/platform
properties. XNU then owns signature allocation, native read-only cs_blob
attachment/reconstitution and executable-page validation as before. No kernel
loader, invalid-code hook or page-valid bit is replaced or pre-marked valid.

Runtime policy sets VALID/SIGNED only after successful verification and requires
HARD/KILL/ENFORCEMENT. It never sets ADHOC, platform/path trust, get-task-allow,
debugging, entitlement or Apple signer type. Invalid-code exceptions, csflags
changes and executable anonymous/file mmap/mprotect exceptions remain denied.
The old64-byte security proof ABI is unchanged; its quarantine flag now denotes
untrusted execution quarantine, while the new separate proof records the
specifically authenticated laboratory exec/attachment and real vnode denials.
The UMS512 native MASTER adds the genuine config_enforce_signed_code feature,
so stock Mach-O loading cannot ignore attachment failures under macOS's default
per-process opt-in policy. All preexisting protection feature groups remain.
The host checker requires the resulting global enforcement variable to be1 and
locked RO/NX. The no-monitor empty-entitlement adjustment authenticates the
vnode/CD again and permits only an absent entitlement object; nonempty objects
still fail closed, and no CE interpreter/context is invented.

Negative root assets contain unsigned code, a changed signed code page and a
damaged CMS signature. The verifier rejects these on actual mounted vnode data.
The next image also contains an independently valid foreign CMS/root/leaf chain,
verified with its own CA by OpenSSL but absent from the primary kernel pins.
All four actual vnode files must be rejected during each native boot.
Host fatal ASan/UBSan also tests real positive bytes, changed header/code/CMS,
truncation and validity boundaries. Positive tests do not authorize untrusted
input or prove EL0 before a genuine native kernel run.

The QEMU checker reads real ARM_THREAD_STATE64 setter input to follow the
loader's ASLR entry. It requires actual EL0t, matching getpid/SVC opcodes,
single-step execution of the first user instruction, the real kernel getpid
handler return, and PID1/no-error return to EL0 after SVC. The program itself
must compare that result and reach its success marker. Native cs_validate_page
outputs must report validated, untainted, executable bytes. All observations
use breakpoints/reads/steps only, with no debugger memory or register writes.
Post-exec counters are sampled at the genuine getpid return in EL1, before the
stock syscall handler restores EL0. The checker rejects EL0 kernel VA reads,
inaccessible addresses and short replies without stale-data fallback. The real
ubc_cs_blob_add return must separately report success.

The public MASTER has the config_enforce_signed_code attribute but no options
declaration. The board now supplies options CONFIG_ENFORCE_SIGNED_CODE through
the original SETUP/config path. Local real generated OSFMK/BSD Makefiles contain
-DCONFIG_ENFORCE_SIGNED_CODE; the unchanged kern_cs.c conditional preprocesses
to process enforcement1, with a missing-option negative control producing0.
This macro is in CONFIG_DEFINES, consumed by MakeInc.def, rather than a guessed
generated-header name. The same actual generated Makefiles are checked in CI;
only a new runtime readback1 with RO/NX can confirm enforcement in that kernel.

This proves only the owned laboratory process when the native test passes.
Native57/run40112465191 now passed TWO real boots of the exact full kernel
SHA2564fc8d0663cbdb9c05d7e19cb3872814459577c4543581e357d928adde462281e.
Global enforcement1/RO/NX, stock attachment return0, native page validation
15/0/0 and EL0/getpid/PID1/success-loop were observed. Fresh getpid-return EL1
counters were exec1/signature1/files3/denials4/vnode-negatives4 in each boot.
Four genuine vnode authorization selftests rejected unsigned code, modified
code page, damaged CMS and an independently valid foreign chain. They do not
claim four separate exec attempts or a measured invalid-page kill. Exact audit,
configuration and two traces: history/native57/summary.json. No guest writes.
It is not Apple code-signing compatibility, a general CMS/AMFI implementation,
launchd/system services, iOS or any physical UMS512 support. The physical phone
remains strictly prohibited.

Host certificate-boundary regression: tests/cms_chain_negative.c links the
actual ums512_lab_codesign.c and pinned BearSSL sources, with a generated
lab_exec_trust.h from the known asset's signing work. Arguments are known file,
foreign-chain file and current epoch. It accepts the known asset, rejects
changed root/leaf certificates and a separate cryptographically valid CMS chain
made by another call to tools/lab_exec_assets.sign. Compile with fatal ASan/
UBSan and the generated crypto include directory. Source/asset/result hashes
are in lab-cms-host-validation.json. These are host checks, not EL0 evidence.
