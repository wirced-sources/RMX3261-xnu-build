/* SPDX-License-Identifier: MIT
 * Physical backend interfaces. Unqualified handoff is refused at runtime.
 * pe_init_fiq must initialize delegated Group1NS delivery for the current CPU,
 * install the XNU interrupt handler and validate SRE/GICR/timer ownership.
 * pe_identify_machine must derive gPEClockFrequencyInfo from qualified ADT/
 * architectural observations, never the upstream legacy/QEMU clock defaults.
 * The offline adapter emits no firmware qualification contract by default.
 */
#pragma once
#include <pexpert/arm64/boot.h>
#include "ums512_hw_policy.h"
#ifdef __cplusplus
extern "C" {
#endif
void ums512_hw_irq_initialize(void);
void ums512_hw_clock_identify(boot_args *);
void ums512_hw_read_handoff(struct ums512_hw_handoff *, uint64_t);
#ifdef __cplusplus
}
#endif
