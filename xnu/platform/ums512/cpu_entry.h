/* UMS512 cold-entry prerequisite checks. No implementation-defined CPU writes.
 * ARM64 assembly only; x9-x14 clobbered, x0 (physical boot_args) preserved.
 * Failure parks with x12 = reason; this is not a recovery mechanism.
 * Values checked here are architectural ID encodings, not MMIO addresses.
 */
#pragma once
#ifdef ASSEMBLER
.macro UMS512_VALIDATE_COLD_CPU
    mov x12, #1
    mrs x9, CurrentEL
    cmp x9, #4                         /* EL1 */
    b.ne Lums512_entry_reject\@
    mov x12, #2
    mrs x9, SCTLR_EL1
    tst x9, #1                         /* MMU off */
    b.ne Lums512_entry_reject\@
    tst x9, #4                         /* D-cache off */
    b.ne Lums512_entry_reject\@
    tst x9, #0x1000                    /* I-cache off */
    b.ne Lums512_entry_reject\@
    mov x12, #3
    mrs x9, MIDR_EL1
    ubfx x10, x9, #24, #8
    cmp x10, #0x41                    /* ARM implementer */
    b.ne Lums512_entry_reject\@
    ubfx x10, x9, #4, #12
    mov x11, #0xd05                   /* Cortex-A55 */
    cmp x10, x11
    b.eq Lums512_part_ok\@
    mov x11, #0xd0a                   /* Cortex-A75 */
    cmp x10, x11
    b.ne Lums512_entry_reject\@
Lums512_part_ok\@:
    mov x12, #4
    mrs x9, ID_AA64MMFR0_EL1
    ubfx x10, x9, #20, #4             /* TGran16: 1 or 2 supports 16K */
    cmp x10, #1
    b.eq Lums512_granule_ok\@
    cmp x10, #2
    b.ne Lums512_entry_reject\@
Lums512_granule_ok\@:
    mov x12, #5
    and x10, x9, #15                  /* >= 40-bit physical address range */
    cmp x10, #2
    b.lo Lums512_entry_reject\@
    mov x12, #6
    mrs x9, CTR_EL0
    and x10, x9, #15                  /* IminLine: 4 words * 2^4 = 64 */
    cmp x10, #4
    b.ne Lums512_entry_reject\@
    ubfx x10, x9, #16, #4
    cmp x10, #4
    b.ne Lums512_entry_reject\@
    b Lums512_entry_ok\@
Lums512_entry_reject\@:
    msr DAIFSet, #15
Lums512_entry_park\@:
    wfe
    b Lums512_entry_park\@
Lums512_entry_ok\@:
.endmacro
#endif
