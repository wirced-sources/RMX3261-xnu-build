/* Data-only XNU 8796 handoff ABI reused from sweet loader.c; no loader/MMIO. */
#pragma once
#include <stdint.h>

struct xnu_boot_video {
    uint64_t base, display, row_bytes, width, height, depth;
};

struct xnu_boot_args {
    uint16_t revision, version;
    uint64_t virt_base, phys_base, mem_size, top_of_kernel_data;
    struct xnu_boot_video video;
    uint32_t machine_type;
    uint64_t device_tree;
    uint32_t device_tree_length;
    char command_line[608];
    uint64_t boot_flags, mem_size_actual;
};

_Static_assert(__builtin_offsetof(struct xnu_boot_args, video) == 40, "XNU video offset");
_Static_assert(__builtin_offsetof(struct xnu_boot_args, command_line) == 108, "XNU command line offset");
_Static_assert(sizeof(struct xnu_boot_args) == 736, "XNU 8796 boot ABI");
