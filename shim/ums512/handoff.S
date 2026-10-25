/* SPDX-License-Identifier: MIT
 * Callable cold EL1 transfer primitive, NOT a Linux Image or loader.
 * Caller must authenticate/copy the kernel and data, prove ownership, clean
 * writes to PoC, qualify CPU/firmware, and quiesce DMA/other CPUs beforehand.
 * x0=entry PA, x1=boot_args PA, x2=owned stack top PA. No address selection.
 * Returns 1 for unsupported EL/cache/alignment; accepted transfer never returns.
 * No EL2 normalization, MMU tables, driver access or physical qualification.
 */
#if defined(__APPLE__)
#define SYMBOL _ums512_handoff_el1
#else
#define SYMBOL ums512_handoff_el1
#endif
.text
.p2align 2
.globl SYMBOL
SYMBOL:
    mrs x9, CurrentEL
    cmp x9, #4
    b.ne 1f
    mrs x9, SCTLR_EL1
    mov x10, #0x1005
    tst x9, x10
    b.ne 1f
    /* XNU reads little-endian boot_args before resetting SCTLR_EL1. */
    tbnz x9, #25, 1f                 /* EE: EL1 data accesses must be LE. */
    cbz x0, 1f
    cbz x1, 1f
    cbz x2, 1f
    tst x0, #3
    b.ne 1f
    tst x1, #7
    b.ne 1f
    tst x2, #15
    b.ne 1f
    msr DAIFSet, #15
    msr SPSel, #1
    mov sp, x2
    mov x9, x0
    mov x0, x1
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    dsb sy
    ic iallu
    dsb sy
    isb
    br x9
1:
    mov x0, #1
    ret
