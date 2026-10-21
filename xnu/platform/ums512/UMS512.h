/* Proposed XNU board policy, compiled in isolation in M0.9. Not a complete machine config. */
#pragma once
#define UMS512 1
#define NO_MONITOR 1
#define NO_ECORE 1 /* Single bootstrap CPU; no Apple E-core scheduling policy. */
#define ARM_ARCH_TIMER 1
#define HAS_GIC_V3 1
#define __ARM_ARCH__ 8
#define __ARM_VMSA__ 8
#define __ARM_VFP__ 4
#define __ARM_COHERENT_CACHE__ 1
#define __ARM_DEBUG__ 8
#define __ARM_16K_PG__ 1 /* Proposed kernel granule, gated on ID_AA64MMFR0_EL1. */
#define __ARM64_PMAP_SUBPAGE_L1__ 1
#define MAX_CPUS 1 /* Bring-up limit, not observed SoC topology (6 A55 + 2 A75). */
#define MAX_CPU_CLUSTERS 1
/* CPU_HAS_APPLE_PAC, Apple sysregs, ARM AMP and SMP are intentionally not enabled. */
