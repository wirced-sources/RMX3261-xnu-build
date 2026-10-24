/* SPDX-License-Identifier: MIT
 * Required physical implementations, intentionally NOT provided as stubs.
 * pe_init_fiq must initialize delegated Group1NS delivery for the current CPU,
 * install the XNU interrupt handler and validate SRE/GICR/timer ownership.
 * pe_identify_machine must derive gPEClockFrequencyInfo from qualified ADT/
 * architectural observations, never the upstream legacy/QEMU clock defaults.
 * Until implemented, a full native link must report these exact dependencies.
 */
#pragma once
#include <pexpert/arm64/boot.h>
#ifdef __cplusplus
extern "C" {
#endif
void ums512_hw_irq_initialize(void);
void ums512_hw_clock_identify(boot_args *);
#ifdef __cplusplus
}
#endif
