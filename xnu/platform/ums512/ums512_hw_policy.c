/* SPDX-License-Identifier: MIT */
#include "ums512_hw_policy.h"

int ums512_hw_contract_check(const struct ums512_hw_handoff *h, uint64_t required, uint64_t mpidr)
{
    if (!h || h->version!=1 || h->bytes!=sizeof(*h) || h->reserved ||
        (h->prerequisites & ~UMS512_HW_KNOWN_FLAGS) ||
        (h->prerequisites & required)!=required ||
        (h->mpidr & ~UINT64_C(0xff00ffffff)) || h->mpidr!=(mpidr & UINT64_C(0xff00ffffff)))
        return HW_CONTRACT;
    /* WAKER may also be RAZ/WI to NS. Require the secure snapshot in addition
     * to any live NS read; zero NS readback alone cannot prove awake state.
     */
    if ((required & UMS512_HW_CPU_IF_OWNED) && ((h->secure_waker & 6u) || (h->secure_rdctlr & 9u)))
        return HW_CONTRACT;
    return HW_OK;
}
static int rate(const struct ums512_hw_rate *r, int required)
{
    if (!required && !r->hz && !r->min_hz && !r->max_hz) return 1;
    return r->min_hz && r->min_hz<=r->hz && r->hz<=r->max_hz && r->max_hz<=UINT32_MAX;
}
static uint64_t gcd(uint64_t a, uint64_t b)
{
    while (b) { uint64_t r=a%b; a=b; b=r; }
    return a;
}
int ums512_hw_clock_check(const struct ums512_hw_handoff *h, uint64_t cntfrq,
    struct ums512_hw_clock_result *out)
{
    /* XNU rtclock_usec_divisor is Hz/1e6: smaller rates would give zero.
     * The architectural CNTFRQ field and XNU timebase conversion are 32-bit.
     * These are ABI/algorithm bounds, NOT a guessed physical frequency range.
     */
    if (!h || !out || cntfrq<1000000 || cntfrq>UINT32_MAX || h->cntfrq!=cntfrq ||
        !rate(&h->bus,1) || !rate(&h->cpu,1) || !rate(&h->memory,0) ||
        !rate(&h->peripheral,0) || h->fixed_hz>UINT32_MAX) return HW_FREQUENCY;
    uint64_t bc=gcd(h->cpu.hz,h->bus.hz), bd=gcd(cntfrq,h->bus.hz);
    /* Exact reduced ratios, no multiplication/truncation/saturation. Outputs
     * are not modified on error. Divisors are nonzero after rate validation.
     */
    struct ums512_hw_clock_result r={cntfrq,h->cpu.hz/bc,h->bus.hz/bc,cntfrq/bd,h->bus.hz/bd};
    *out=r;
    return HW_OK;
}
int ums512_hw_gic_check(uint32_t ctlr, uint32_t rdctlr, uint32_t waker,
    uint32_t secure_groups, uint32_t secure_modifiers, uint32_t enabled, uint32_t pending, uint32_t active,
    uint32_t configuration, uint32_t intid)
{
    if (intid<16 || intid>=32) return HW_GIC_STATE;
    uint32_t bit=UINT32_C(1)<<intid;
    /* NS view: ARE_NS bit4, EnableGrp1A bit1. DS bit6 must remain zero;
     * single-security-state QEMU defaults are expressly not accepted.
     * Firmware must already have selected Group1NS for the owned PPI.
     * IGROUPR0/IGRPMODR0 are RAZ/WI to NS when DS=0. Group values here are
     * qualified secure-world snapshots, NOT pretend EL1 readback. Enabled/
     * pending/active are live NS views (Secure interrupt bits read zero).
     */
    if ((ctlr & ((1u<<31)|(1u<<6)|(1u<<4)|(1u<<1)))!=((1u<<4)|(1u<<1)) ||
        (rdctlr & (1u|8u)) || (waker & 6u) || !(secure_groups & bit) || (secure_modifiers & bit) ||
        (enabled & ~bit) || pending || active ||
        (configuration & (3u<<((intid-16)*2)))) return HW_GIC_STATE;
    return HW_OK;
}
