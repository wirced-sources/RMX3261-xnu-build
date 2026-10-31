/* SPDX-License-Identifier: MIT. Only called by the genuine arm_init checkpoint.
 * Still under start.s's V=P + KVA bootstrap tables; no PE/interrupts/drivers ran.
 * Clean every byte XNU could have dirtied before disabling caches. Continue at
 * the identity alias INSIDE XNU, then enter the saved Linux courier trampoline.
 * x0=boot_args KVA, x1=return PA. Architectural EL1 registers only.
 */
#if defined(__APPLE__)
#define SYM _ums512_xnu_return_to_linux
#else
#define SYM ums512_xnu_return_to_linux
#endif
.text
.p2align 2
.globl SYM
SYM:
    msr DAIFSet, #15
    ldr x2, [x0, #8]                 /* virtBase */
    ldr x3, [x0, #16]                /* physBase */
    ldr x4, [x0, #32]                /* topOfKernelData */
    sub x5, x0, x2
    add x5, x5, x3                  /* boot_args PA passed to courier */
    sub x4, x4, x3
    add x4, x4, x2
    mov x6, x2
1:
    dc civac, x6
    add x6, x6, #64
    cmp x6, x4
    b.lo 1b
    dsb sy
    adr x9, 2f
    sub x9, x9, x2
    add x9, x9, x3
    br x9
2:                                  /* V=P before clearing SCTLR.M */
    mrs x10, SCTLR_EL1
    bic x10, x10, #1
    bic x10, x10, #4
    bic x10, x10, #0x1000
    msr SCTLR_EL1, x10
    isb
    tlbi vmalle1
    dsb sy
    ic iallu
    dsb sy
    isb
    mov x0, x5
    br x1
