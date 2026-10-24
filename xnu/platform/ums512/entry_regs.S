/* A callable EL1 register probe, NOT a reset entry, EL transition or XNU loader. */
#if defined(__APPLE__)
#define SYM(x) _##x
#else
#define SYM(x) x
#endif
.text
.p2align 2
.globl SYM(ums512_read_el1_state)
SYM(ums512_read_el1_state):
    mrs x1, CurrentEL
    mrs x2, SCTLR_EL1
    stp x1, x2, [x0]
    mrs x1, MPIDR_EL1
    mrs x2, CNTFRQ_EL0
    stp x1, x2, [x0, #16]
    mrs x1, ID_AA64MMFR0_EL1
    str x1, [x0, #32]
    ret
