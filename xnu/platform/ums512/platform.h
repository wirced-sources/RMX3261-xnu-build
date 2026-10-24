/* Offline UMS512 platform primitives. No PE registration or hardware driver. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "../../../shim/ums512/xnu_boot.h"

struct ums512_extent { uint64_t base, size; };
struct ums512_plan {
    struct ums512_extent ram, kernel, args, adt, stack, log;
    uint64_t virt_base, top;
    uint32_t page_size;
};
enum ums512_result {
    UMS512_OK, UMS512_INVALID, UMS512_RANGE, UMS512_OVERLAP,
    UMS512_UNSUPPORTED, UMS512_NOT_FOUND
};
/* Success is structural only. Live ownership, ADT contents and mappings are external gates. */
int ums512_validate_plan(const struct ums512_plan *, const struct ums512_extent *, size_t);
int ums512_boot_args(struct xnu_boot_args *, const struct ums512_plan *,
                    const struct ums512_extent *, size_t, const char *, size_t);
/* Pure selection from caller-supplied GICR_TYPER snapshots; never reads MMIO. */
int ums512_gicr_select(uint64_t mpidr, const uint64_t *typers, size_t count, uint64_t *pa);
enum ums512_irq { UMS512_IRQ_OTHER, UMS512_IRQ_TIMER, UMS512_IRQ_SGI, UMS512_IRQ_SPURIOUS };
enum ums512_irq ums512_irq_class(uint64_t iar);
int ums512_timer_ticks(uint64_t nanoseconds, uint32_t measured_hz, uint64_t *ticks);

struct ums512_entry_state {
    uint64_t current_el, sctlr, mpidr, cntfrq, mmfr0;
};
/* Callable only at EL1 with a valid stack and writable 40-byte output. */
void ums512_read_el1_state(struct ums512_entry_state *);
int ums512_entry_check(const struct ums512_entry_state *);
/* Full physical-target prerequisite gate on caller-supplied architectural
 * snapshots. No register writes, EL transition, probing or hardware approval.
 * MMFR1.PAN must match UMS512.h's real PAN feature; MIDR/CTR/affinity must match
 * the Cortex build policy and committed CPU facts. The older ABI is preserved.
 */
int ums512_entry_check_target(const struct ums512_entry_state *, uint64_t mmfr1,
                             uint64_t midr, uint64_t ctr);

/* Single CPU, caller-owned RAM. No UART, allocation, persistence or cache maintenance. */
struct ums512_log {
    uint32_t magic, version, head, count;
    uint8_t bytes[256];
};
_Static_assert(sizeof(struct ums512_log) == 272, "diagnostic ABI");
void ums512_log_init(struct ums512_log *);
int ums512_log_put(struct ums512_log *, uint8_t);
