/* SPDX-License-Identifier: MIT
 * UMS512 physical handoff data and pure validation. No MMIO or success defaults.
 * Little endian ADT property /chosen/ums512,hw-handoff, version 1.
 * This is a loader contract, NOT evidence that firmware satisfied it. The
 * current offline adapter deliberately does not emit this property.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#define UMS512_HW_NS_EL1             (UINT64_C(1) << 0)
#define UMS512_HW_TIMER_ACCESS       (UINT64_C(1) << 1)
#define UMS512_HW_CLOCKS_STABLE      (UINT64_C(1) << 2)
#define UMS512_HW_GIC_MMIO_ACCESS    (UINT64_C(1) << 3)
#define UMS512_HW_CPU_IF_OWNED       (UINT64_C(1) << 4)
#define UMS512_HW_VTIMER_OWNED       (UINT64_C(1) << 5)
#define UMS512_HW_NS_QUIESCED        (UINT64_C(1) << 6)
#define UMS512_HW_CLOCK_REQUIRED (UMS512_HW_NS_EL1 | UMS512_HW_TIMER_ACCESS | UMS512_HW_CLOCKS_STABLE)
#define UMS512_HW_IRQ_REQUIRED (UMS512_HW_NS_EL1 | UMS512_HW_TIMER_ACCESS | UMS512_HW_GIC_MMIO_ACCESS | \
    UMS512_HW_CPU_IF_OWNED | UMS512_HW_VTIMER_OWNED | UMS512_HW_NS_QUIESCED)
#define UMS512_HW_KNOWN_FLAGS (UMS512_HW_CLOCK_REQUIRED | UMS512_HW_IRQ_REQUIRED)

struct ums512_hw_rate { uint64_t hz, min_hz, max_hz; };
struct ums512_hw_handoff {
    uint32_t version, bytes;
    uint64_t prerequisites, mpidr, cntfrq;
    struct ums512_hw_rate bus, cpu, memory, peripheral;
    uint64_t fixed_hz;
    uint64_t gicd_base, gicd_size, gicr_base, gicr_size, gicr_stride;
    uint32_t virtual_intid, reserved;
    uint32_t secure_igroupr0, secure_igrpmodr0, secure_waker, secure_rdctlr;
};
_Static_assert(sizeof(struct ums512_hw_handoff)==200, "hardware handoff wire size");
_Static_assert(offsetof(struct ums512_hw_handoff,gicd_base)==136, "hardware handoff wire offset");
struct ums512_hw_clock_result {
    uint64_t timebase, bus_cpu_num, bus_cpu_den, bus_dec_num, bus_dec_den;
};
enum ums512_hw_error { HW_OK, HW_CONTRACT, HW_FREQUENCY, HW_GIC_STATE };
int ums512_hw_contract_check(const struct ums512_hw_handoff *, uint64_t, uint64_t);
int ums512_hw_clock_check(const struct ums512_hw_handoff *, uint64_t, struct ums512_hw_clock_result *);
/* Architectural NS distributor view. No DS/security/group changes allowed. */
int ums512_hw_gic_check(uint32_t ctlr, uint32_t rdctlr, uint32_t waker,
    uint32_t secure_groups, uint32_t secure_modifiers, uint32_t enabled, uint32_t pending, uint32_t active,
    uint32_t configuration, uint32_t intid);
