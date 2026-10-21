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
/* Full 16KB L1 covers 47 VA bits. The stock MacOSX ARM_LARGE_MEMORY
 * link address (-2TB) is outside the 39-bit subpage-L1 TTBR1 range. */
#define __ARM64_PMAP_SUBPAGE_L1__ 0
#define MAX_CPUS 1 /* Bring-up limit, not observed SoC topology (6 A55 + 2 A75). */
#define MAX_CPU_CLUSTERS 1
/* CPU_HAS_APPLE_PAC, Apple sysregs, ARM AMP and SMP are intentionally not enabled. */

/* Architectural GICv3 register encodings, matching Arm IHI0069 and upstream
 * pexpert/arm64/VMAPPLE.h. These are offsets, not UMS512 MMIO bases. They allow
 * the original PE source to compile. Its Group0/FIQ policy is NOT a working
 * UMS512 Group1NS backend and remains a runtime integration blocker.
 */
#define GIC_SPURIOUS_IRQ 1023
#define GICR_PE_SIZE 0x20000
#define GICD_CTLR 0x0
#define GICD_CTLR_ENABLEGRP0 0x1
#define GICR_TYPER 0x08
#define GICR_WAKER 0x14
#define GICR_IGROUPR0 0x10080
#define GICR_ISENABLER0 0x10100
#define GICR_TYPER_AFFINITY_VALUE_SHIFT 32
#define GICR_TYPER_LAST 0x10
#define GICR_WAKER_PROCESSORSLEEP 0x2
#define GICR_WAKER_CHILDRENASLEEP 0x4
#define ICC_CTLR_EOIMODE 0x1
#define ICC_SRE_SRE 0x1
