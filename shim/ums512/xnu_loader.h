/* SPDX-License-Identifier: MIT
 * Bounded copy stage for an authenticated caller-owned payload. No PA choices,
 * FDL, Linux driver reuse, MMIO, EL2 normalization or hardware-ready container.
 */
#pragma once
#include "../../xnu/platform/ums512/platform.h"
#define UMS512_LOADER_MAX_SEGMENTS 32
#define UMS512_LOADER_OWNERSHIP 0x0fu /* authenticated payload, RAM, DMA/CPUs quiet */
struct ums512_load_segment {
    uint64_t pa, file_offset, file_bytes, memory_bytes, protection;
};
struct ums512_load_request {
    struct ums512_plan plan;
    const unsigned char *file;
    uint64_t file_bytes, entry_pa;
    const struct xnu_boot_args *args;
    const unsigned char *adt;
    const struct ums512_extent *live;
    size_t live_count, segment_count;
    uint64_t qualified; /* assertion from future qualified caller, NOT proof */
    struct ums512_load_segment segments[UMS512_LOADER_MAX_SEGMENTS];
};
int ums512_xnu_validate_load(const struct ums512_load_request *);
int ums512_xnu_load_and_enter(const struct ums512_load_request *);
