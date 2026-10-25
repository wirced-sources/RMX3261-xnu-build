/* UMS512 cold-entry prerequisite checks. No implementation-defined CPU writes.
 * ARM64 assembly only; x9-x14 clobbered, x0 (physical boot_args) preserved.
 * Failure parks with x12 = reason; this is not a recovery mechanism.
 * Values checked here are architectural ID encodings, not MMIO addresses.
 */
#pragma once
#ifdef ASSEMBLER
.macro UMS512_VALIDATE_COLD_CPU
    /* Numeric local labels work in Apple Clang15 and upstream LLVM alike. */
    mov x12, #1
    mrs x9, CurrentEL
    cmp x9, #4                         /* EL1 */
    b.ne 3f
    mov x12, #2
    mrs x9, SCTLR_EL1
    tst x9, #1                         /* MMU off */
    b.ne 3f
    tst x9, #4                         /* D-cache off */
    b.ne 3f
    tst x9, #0x1000                    /* I-cache off */
    b.ne 3f
#if defined(UMS512_HARDWARE_TARGET) && UMS512_HARDWARE_TARGET
    mov x12, #7
    tbnz x9, #25, 3f                 /* EE: boot_args is little endian. */
#endif
    mov x12, #3
    mrs x9, MIDR_EL1
    ubfx x10, x9, #24, #8
    cmp x10, #0x41                    /* ARM implementer */
    b.ne 3f
    ubfx x10, x9, #4, #12
    mov x11, #0xd05                   /* Cortex-A55 */
    cmp x10, x11
    b.eq 1f
    mov x11, #0xd0a                   /* Cortex-A75 */
    cmp x10, x11
    b.ne 3f
1:
    mov x12, #4
    mrs x9, ID_AA64MMFR0_EL1
    ubfx x10, x9, #20, #4             /* TGran16: 1 or 2 supports 16K */
    cmp x10, #1
    b.eq 2f
    cmp x10, #2
    b.ne 3f
2:
    mov x12, #5
    and x10, x9, #15                  /* >= 40-bit physical address range */
    cmp x10, #2
    b.lo 3f
    mov x12, #6
    mrs x9, CTR_EL0
    and x10, x9, #15                  /* IminLine: 4 words * 2^4 = 64 */
    cmp x10, #4
    b.ne 3f
    ubfx x10, x9, #16, #4
    cmp x10, #4
    b.ne 3f
    b 5f
3:
    msr DAIFSet, #15
4:
    wfe
    b 4b
5:
.endmacro
#endif
