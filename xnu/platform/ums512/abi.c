#include "platform.h"
#include "UMS512.h"
#if defined(CPU_HAS_APPLE_PAC) || defined(APPLE_ARM64_ARCH_FAMILY)
#error "UMS512 must not select Apple CPU features"
#endif
#define OFF(f, n) _Static_assert(offsetof(struct xnu_boot_args, f) == n, #f)
OFF(revision, 0); OFF(version, 2); OFF(virt_base, 8); OFF(phys_base, 16);
OFF(mem_size, 24); OFF(top_of_kernel_data, 32); OFF(video, 40);
OFF(machine_type, 88); OFF(device_tree, 96); OFF(device_tree_length, 104);
OFF(command_line, 108); OFF(boot_flags, 720); OFF(mem_size_actual, 728);
_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8, "ARM64 LP64 required");
_Static_assert(sizeof(struct ums512_entry_state) == 40, "probe store offsets");
