/* SPDX-License-Identifier: MIT
 * Physical UMS512 GICv3 bootstrap: only the owned virtual timer PPI27 and this
 * CPU's NS interface. No distributor/group/security/wake/routing writes.
 * Register facts: Arm IHI0069; pinned public vendor inputs listed in docs.
 * GPL vendor implementation bodies are not incorporated here.
 */
#if !UMS512_HARDWARE_TARGET
#error Physical interrupt backend must not enter the QEMU kernel
#endif
#include <stdint.h>
#include <string.h>
#include <kern/debug.h>
#include <arm/cpu_data_internal.h>
#include <arm/rtclock.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <pexpert/arm64/board_config.h>
#include <libkern/section_keywords.h>
#include "ums512_hw_backend.h"
#include "platform.h"
#include "facts.h"

_Static_assert(MAX_CPUS==1, "physical IRQ lifecycle is currently UP only");
_Static_assert(sizeof(ums512_reserved)>0, "hardware facts present");
enum {
    HW_D_CTLR=0, HW_D_TYPER=4, HW_D_PIDR2=0xffe8, HW_D_ISENABLER=0x100,
    HW_R_CTLR=0, HW_R_TYPER=8, HW_R_WAKER=0x14, HW_R_PIDR2=0xffe8,
    HW_R_ENABLE=0x10100, HW_R_DISABLE=0x10180,
    HW_R_PENDING=0x10200, HW_R_ACTIVE=0x10300, HW_R_PRIORITY=0x10400,
    HW_R_CONFIG1=0x10c04
};
static SECURITY_READ_ONLY_LATE(vm_offset_t) hw_rdist;
static SECURITY_READ_ONLY_LATE(uint64_t) hw_affinity;
static SECURITY_READ_ONLY_LATE(unsigned) hw_irq_ready;

static uint32_t read32(vm_offset_t base, unsigned off)
{ return *(volatile uint32_t *)(base+off); }
static void write32(vm_offset_t base, unsigned off, uint32_t value)
{ *(volatile uint32_t *)(base+off)=value; }
static void barrier(void) { __asm__ volatile("dsb sy; isb":::"memory"); }
static uint64_t counter(void)
{ __asm__ volatile("isb":::"memory"); return __builtin_arm_rsr64("CNTVCT_EL0"); }
static void wait_rwp(void)
{
    uint64_t start=counter(),hz=gPEClockFrequencyInfo.timebase_frequency_hz;
    unsigned remaining=1000000; /* Also bound a broken/non-advancing counter. */
    while (read32(hw_rdist,HW_R_CTLR)&8) {
        if (!--remaining || counter()-start>hz) panic("UMS512HW: redistributor RWP timeout");
        __asm__ volatile("yield");
    }
}
static void eoi(uint64_t iar)
{
    barrier(); /* Device deassertion must precede priority drop/deactivate. */
    __builtin_arm_wsr64("ICC_EOIR1_EL1",iar);
    __asm__ volatile("isb":::"memory");
}
static void interrupt(void *target __unused,void *refcon __unused,
    void *nub __unused,int source __unused)
{
    uint64_t iar=__builtin_arm_rsr64("ICC_IAR1_EL1");
    __asm__ volatile("dsb sy":::"memory");
    uint32_t id=(uint32_t)(iar&0xffffff);
    if (id>=1020 && id<=1023) return; /* Special INTIDs are never EOI'd. */
    if (!hw_irq_ready || id!=UMS512_VTIMER_INTID ||
        (__builtin_arm_rsr64("MPIDR_EL1")&UINT64_C(0xff00ffffff))!=hw_affinity) {
        eoi(iar);
        panic("UMS512HW: unexpected Group1NS interrupt %u",id);
    }
    /* Real XNU timer service, not a demonstration callback. The interrupt
     * source is deasserted/rearmed by the stock rtclock/deadline machinery.
     */
    getCpuDatap()->cpu_decrementer=-1;
    rtclock_intr(FALSE);
    eoi(iar); /* EOImode=0: no split ICC_DIR operation. */
}
void ums512_hw_irq_initialize(void)
{
    struct ums512_hw_handoff h;
    DTEntry node;
    const void *p;
    unsigned bytes;
    if (hw_irq_ready) panic("UMS512HW: repeated/secondary IRQ initialization unsupported");
    ums512_hw_read_handoff(&h,UMS512_HW_IRQ_REQUIRED);
    if (h.gicd_base!=UMS512_GICD_BASE || h.gicd_size!=0x20000 ||
        h.gicr_base!=UMS512_GICR_BASE || h.gicr_size!=UMS512_GICR_SIZE ||
        h.gicr_stride!=UMS512_GICR_STRIDE || h.virtual_intid!=UMS512_VTIMER_INTID ||
        !gPEClockFrequencyInfo.timebase_frequency_hz ||
        __builtin_arm_rsr64("CNTFRQ_EL0")!=gPEClockFrequencyInfo.timebase_frequency_hz)
        panic("UMS512HW: physical IRQ handoff geometry/timebase mismatch");
    /* Verify the translated ADT against independent pinned facts. No soc-base
     * addition on unchecked integers, no QEMU base or arbitrary MMIO mapping.
     */
    uint64_t ranges[4],stride;
    uint32_t timer;
    if (SecureDTLookupEntry(NULL,"/arm-io/gic",&node)!=kSuccess ||
        SecureDTGetProperty(node,"reg",&p,&bytes)!=kSuccess || bytes!=sizeof(ranges))
        panic("UMS512HW: invalid GIC ADT");
    memcpy(ranges,p,sizeof(ranges));
    if (ranges[0]!=0 || ranges[1]!=h.gicd_size || ranges[2]!=h.gicr_base-h.gicd_base || ranges[3]!=h.gicr_size ||
        pe_arm_get_soc_base_phys()!=h.gicd_base ||
        SecureDTGetProperty(node,"redistributor-stride",&p,&bytes)!=kSuccess || bytes!=8)
        panic("UMS512HW: GIC ranges mismatch");
    memcpy(&stride,p,8);
    if (stride!=h.gicr_stride || SecureDTLookupEntry(NULL,"/timer",&node)!=kSuccess ||
        SecureDTGetProperty(node,"ums512,virtual-intid",&p,&bytes)!=kSuccess || bytes!=4)
        panic("UMS512HW: invalid virtual timer ADT");
    memcpy(&timer,p,4);
    if (timer!=h.virtual_intid) panic("UMS512HW: timer PPI mismatch");
    /* Do not attempt to enable SRE or compensate for firmware traps. Even
     * these reads require the qualified upper-EL access contract above.
     */
    if (!(__builtin_arm_rsr64("ICC_SRE_EL1")&1) ||
        (__builtin_arm_rsr64("CNTV_CTL_EL0")&1) ||
        (__builtin_arm_rsr64("ICC_IGRPEN1_EL1")&1) ||
        (__builtin_arm_rsr64("ICC_CTLR_EL1")&1))
        panic("UMS512HW: SRE/timer/CPU interface not handed off quiescent");
    vm_offset_t dist=ml_io_map(h.gicd_base,h.gicd_size);
    vm_offset_t redist=ml_io_map(h.gicr_base,h.gicr_size);
    if (!dist || !redist || (read32(dist,HW_D_PIDR2)&0xf0)!=0x30)
        panic("UMS512HW: cannot map physical GICv3");
    uint64_t typers[UMS512_GICR_SIZE/UMS512_GICR_STRIDE],selected;
    size_t n=0;
    for (;n<sizeof(typers)/sizeof(typers[0]);) {
        vm_offset_t rd=redist+n*h.gicr_stride;
        if ((read32(rd,HW_R_PIDR2)&0xf0)!=0x30) panic("UMS512HW: invalid redistributor ID");
        typers[n]=*(volatile uint64_t *)(rd+HW_R_TYPER);
        if (typers[n++]&16) break;
    }
    unsigned seen=0;
    for (size_t j=0;j<n;j++) {
        unsigned index=0;
        while (index<sizeof(ums512_cpu_affinities)/sizeof(ums512_cpu_affinities[0]) &&
            (typers[j]>>32)!=ums512_cpu_affinities[index]) index++;
        if (index==sizeof(ums512_cpu_affinities)/sizeof(ums512_cpu_affinities[0]) || (seen&(1u<<index)))
            panic("UMS512HW: unknown/duplicate redistributor affinity");
        seen|=1u<<index;
    }
    if (seen!=((1u<<(sizeof(ums512_cpu_affinities)/sizeof(ums512_cpu_affinities[0])))-1))
        panic("UMS512HW: incomplete redistributor topology");
    if (ums512_gicr_select(h.mpidr,typers,n,&selected)) panic("UMS512HW: invalid GICR affinity/layout");
    hw_rdist=redist+(selected-h.gicr_base);
    int core_ok=0;
    uint32_t midr=(uint32_t)__builtin_arm_rsr64("MIDR_EL1");
    for (size_t i=0;i<sizeof(ums512_cpu_affinities)/sizeof(ums512_cpu_affinities[0]);i++)
        if (h.mpidr==ums512_cpu_affinities[i] && (midr>>24)==0x41 &&
            ((midr>>4)&0xfff)==ums512_cpu_parts[i]) core_ok=1;
    if (!core_ok || ums512_hw_gic_check(read32(dist,HW_D_CTLR),read32(hw_rdist,HW_R_CTLR),
        read32(hw_rdist,HW_R_WAKER),h.secure_igroupr0,h.secure_igrpmodr0,read32(hw_rdist,HW_R_ENABLE),
        read32(hw_rdist,HW_R_PENDING),read32(hw_rdist,HW_R_ACTIVE),read32(hw_rdist,HW_R_CONFIG1),timer))
        panic("UMS512HW: secure delegation/ownership/state not acceptable");
    /* No runtime SPI drivers yet. Refuse enabled NS SPIs instead of disabling
     * firmware interrupts or installing a catch-all success handler.
     */
    unsigned nr=((read32(dist,HW_D_TYPER)&31)+1)*32;
    for (unsigned id=32;id<nr;id+=32)
        if (read32(dist,HW_D_ISENABLER+id/8)) panic("UMS512HW: NS SPI sources not quiesced");
    /* Only now may we change the explicitly owned PPI and NS CPU interface.
     * All CPU IRQ/FIQ masks stay set; ml_install_interrupt_handler restores
     * their prior state. Other cores and Secure firmware must stay quiescent.
     */
    uint32_t bit=UINT32_C(1)<<timer;
    write32(hw_rdist,HW_R_DISABLE,bit); wait_rwp(); barrier();
    *(volatile uint8_t *)(hw_rdist+HW_R_PRIORITY+timer)=0xa0; /* Kernel priority policy, not a hardware frequency. */
    __builtin_arm_wsr64("ICC_CTLR_EL1",__builtin_arm_rsr64("ICC_CTLR_EL1")&~UINT64_C(2));
    __builtin_arm_wsr64("ICC_BPR1_EL1",0);
    __builtin_arm_wsr64("ICC_PMR_EL1",0xff); barrier();
    uint64_t ctlr=__builtin_arm_rsr64("ICC_CTLR_EL1");
    unsigned priority_bits=(unsigned)((ctlr>>8)&7)+1;
    /* BPR1 rounds writes below its implemented minimum upwards. In NS view
     * the minimum can be 8-PriorityBits; zero readback is not mandatory.
     */
    if ((ctlr&3) || priority_bits<5 || priority_bits>8 ||
        __builtin_arm_rsr64("ICC_PMR_EL1")<=0xa0 ||
        __builtin_arm_rsr64("ICC_BPR1_EL1")>8-priority_bits ||
        *(volatile uint8_t *)(hw_rdist+HW_R_PRIORITY+timer)!=0xa0)
        panic("UMS512HW: CPU priority/EOI configuration denied");
    hw_affinity=h.mpidr;
    ml_install_interrupt_handler(NULL,0,NULL,interrupt,NULL);
    hw_irq_ready=1; barrier();
    write32(hw_rdist,HW_R_ENABLE,bit); wait_rwp(); barrier();
    if (!(read32(hw_rdist,HW_R_ENABLE)&bit)) panic("UMS512HW: timer PPI enable denied");
    __builtin_arm_wsr64("ICC_IGRPEN1_EL1",1); barrier();
    if (!(__builtin_arm_rsr64("ICC_IGRPEN1_EL1")&1)) panic("UMS512HW: NS CPU interface enable denied");
}
