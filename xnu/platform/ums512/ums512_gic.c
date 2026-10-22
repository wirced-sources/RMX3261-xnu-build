/* SPDX-License-Identifier: MIT.
 * QEMU virt GICv3 Group1NS backend. DT ranges and register state are validated.
 * Physical UMS512 initialization is deliberately refused until its firmware
 * security/redistributor policy is established offline. No Apple Group0 route.
 */
#include <stdint.h>
#include <string.h>
#include <kern/debug.h>
#include <arm64/proc_reg.h>
#include <arm/cpu_data_internal.h>
#include <arm/rtclock.h>
#include <machine/machine_routines.h>
#include <mach/machine.h>
#include <pexpert/device_tree.h>
#include <pexpert/pexpert.h>
#include <libkern/section_keywords.h>

struct ums512_irq_proof {
    uint64_t initialized,irq_entries,timer_interrupts,timer_returns;
    uint64_t spurious,sgi_interrupts,last_intid,distributor_control;
};
volatile struct ums512_irq_proof ums512_irq_proof;
struct ums512_cpu_topology_proof {
    uint64_t published,num_cpus,max_cpu_id,boot_cpu_id;
    uint64_t boot_phys_id,current_affinity,machine_max_cpus,reserved0;
};
volatile struct ums512_cpu_topology_proof ums512_cpu_topology_proof;
_Static_assert(sizeof(struct ums512_cpu_topology_proof)==64,"public CPU topology proof ABI");
static vm_offset_t distributor,redistributor;

void ums512_gic_init(void);
uint64_t ums512_gic_sgi_count(void);
void ums512_gic_send_self_sgi(void);
void ums512_qemu_finalize_cpu_topology(void);
static uint32_t read32(vm_offset_t base,uint32_t offset)
{ return *(volatile uint32_t *)(base+offset); }
static void write32(vm_offset_t base,uint32_t offset,uint32_t value)
{ *(volatile uint32_t *)(base+offset)=value; }
static void barrier(void) { __asm__ volatile("dsb sy; isb":::"memory"); }
static void wait_clear(vm_offset_t base,uint32_t offset,uint32_t bits)
{
    uint64_t start=__builtin_arm_rsr64("CNTVCT_EL0");
    uint64_t frequency=__builtin_arm_rsr64("CNTFRQ_EL0");
    while (read32(base,offset)&bits) {
        if (__builtin_arm_rsr64("CNTVCT_EL0")-start>frequency) {
            panic("UMS512 GIC: timed out waiting for register %x",offset);
        }
        __asm__ volatile("yield");
    }
}
static void interrupt(void *target __unused,void *refcon __unused,
    void *nub __unused,int source __unused)
{
    uint64_t iar=__builtin_arm_rsr64("ICC_IAR1_EL1");
    uint32_t id=(uint32_t)(iar&0xffffff);
    ums512_irq_proof.irq_entries++;
    ums512_irq_proof.last_intid=id;
    if (id>=1020 && id<=1023) { ums512_irq_proof.spurious++; return; }
    if (id==27) {
        ums512_irq_proof.timer_interrupts++;
        getCpuDatap()->cpu_decrementer=-1;
        rtclock_intr(FALSE);
        ums512_irq_proof.timer_returns++;
    } else if (id==0) {
        /* Reserved bootstrap SGI for delivery validation; not an SMP IPI API. */
        ums512_irq_proof.sgi_interrupts++;
    } else { panic("UMS512 GIC: unhandled Group1 interrupt %u",id); }
    barrier();
    __builtin_arm_wsr64("ICC_EOIR1_EL1",iar);
    __asm__ volatile("isb":::"memory");
}

void ums512_gic_init(void)
{
    DTEntry root,node;
    const void *prop;
    unsigned bytes;
    static const char model[]="qemu,virt";
    if (SecureDTLookupEntry(NULL,"/",&root)!=kSuccess ||
        SecureDTGetProperty(root,"model",&prop,&bytes)!=kSuccess ||
        bytes!=sizeof(model) || memcmp(prop,model,sizeof(model))) {
        panic("UMS512 GIC: physical firmware security state is not verified");
    }
    if (ums512_irq_proof.initialized) { panic("UMS512 GIC: unexpected secondary CPU initialization"); }
    if (SecureDTLookupEntry(NULL,"/arm-io/gic",&node)!=kSuccess ||
        SecureDTGetProperty(node,"reg",&prop,&bytes)!=kSuccess || bytes!=32) {
        panic("UMS512 GIC: missing validated DT register ranges");
    }
    uint64_t ranges[4];memcpy(ranges,prop,sizeof(ranges));
    uint64_t soc=pe_arm_get_soc_base_phys();
    if (!soc || ranges[0]>UINT64_MAX-soc || ranges[2]>UINT64_MAX-soc ||
        ranges[1]<0x10000 || ranges[1]>0x1000000 || ranges[3]<0x20000 || ranges[3]>0x1000000) {
        panic("UMS512 GIC: invalid DT register ranges");
    }
    distributor=ml_io_map(soc+ranges[0],ranges[1]);
    vm_offset_t rbase=ml_io_map(soc+ranges[2],ranges[3]);
    if (!distributor || !rbase || (read32(distributor,0xffe8)&0xf0)!=0x30) {
        panic("UMS512 GIC: cannot map a GICv3 controller");
    }
    uint32_t control=read32(distributor,0);
    /* QEMU security=off starts with DS=1 and affinity routing already on.
     * Refuse other states rather than demoting a physical security domain.
     */
    if (!(control&(1u<<6)) || !(control&(1u<<4))) {
        panic("UMS512 GIC: unsupported distributor security/affinity state");
    }
    uint64_t mpidr=__builtin_arm_rsr64("MPIDR_EL1");
    uint32_t affinity=(uint32_t)(mpidr&0xffffff)|(uint32_t)((mpidr>>8)&0xff000000);
    for (uint64_t offset=0;offset+0x20000<=ranges[3];) {
        uint64_t typer=*(volatile uint64_t *)(rbase+offset+8);
        if ((uint32_t)(typer>>32)==affinity) { redistributor=rbase+offset;break; }
        if (typer&16) { break; }
        offset+=(typer&2)?0x40000:0x20000;
    }
    if (!redistributor) { panic("UMS512 GIC: no matching redistributor affinity"); }
    write32(distributor,0,control&~3u);wait_clear(distributor,0,1u<<31);
    write32(redistributor,0x14,read32(redistributor,0x14)&~2u);
    wait_clear(redistributor,0x14,4);
    write32(redistributor,0x10180,UINT32_MAX); /* Disable before changing groups. */
    wait_clear(redistributor,0,8);
    write32(redistributor,0x10280,UINT32_MAX);
    write32(redistributor,0x10380,UINT32_MAX);
    write32(redistributor,0x10080,UINT32_MAX); /* All SGI/PPI Group1NS. */
    for (uint32_t off=0x10400;off<0x10420;off+=4) { write32(redistributor,off,0x80808080); }
    /* Virtual timer PPI27 is level-sensitive, SGI0 is architectural edge. */
    uint32_t configuration=read32(redistributor,0x10c04)&~(3u<<22);
    write32(redistributor,0x10c04,configuration);
    __builtin_arm_wsr64("ICC_SRE_EL1",__builtin_arm_rsr64("ICC_SRE_EL1")|1);
    __asm__ volatile("isb":::"memory");
    if (!(__builtin_arm_rsr64("ICC_SRE_EL1")&1)) { panic("UMS512 GIC: system register access denied"); }
    __builtin_arm_wsr64("ICC_IGRPEN0_EL1",0);
    __builtin_arm_wsr64("ICC_IGRPEN1_EL1",0);
    __builtin_arm_wsr64("ICC_CTLR_EL1",__builtin_arm_rsr64("ICC_CTLR_EL1")&~UINT64_C(2));
    __builtin_arm_wsr64("ICC_BPR1_EL1",0);
    __builtin_arm_wsr64("ICC_PMR_EL1",0xff);
    ml_install_interrupt_handler(NULL,0,NULL,interrupt,NULL);
    write32(redistributor,0x10100,(1u<<27)|1u);
    wait_clear(redistributor,0,8);barrier();
    write32(distributor,0,control|2u);wait_clear(distributor,0,1u<<31);
    __builtin_arm_wsr64("ICC_IGRPEN1_EL1",1);barrier();
    ums512_irq_proof.distributor_control=read32(distributor,0);
    ums512_irq_proof.initialized=1;
}

uint64_t ums512_gic_sgi_count(void) { return ums512_irq_proof.sgi_interrupts; }
/* Platform Expert calls this after its real resource initialization. ARM's
 * ml_set_max_cpus publishes completion of enumeration; it neither creates CPUs
 * nor changes machine_info. The latter was set by machine_conf from read-only
 * parsed topology. This profile supports exactly the already executing CPU.
 * Do not instantiate a fictitious IOCPU/interrupt controller or claim CPU-on.
 */
void ums512_qemu_finalize_cpu_topology(void)
{
    const ml_topology_info_t *topology=ml_get_topology_info();
    uint64_t affinity=__builtin_arm_rsr64("MPIDR_EL1")&UINT64_C(0xff00ffffff);
    if (!ums512_irq_proof.initialized || ums512_cpu_topology_proof.published ||
        !topology || topology->num_cpus!=1 || topology->max_cpu_id!=0 ||
        !topology->boot_cpu || topology->boot_cpu->cpu_id!=0 ||
        topology->boot_cpu->phys_id!=0 || affinity!=0 || machine_info.max_cpus!=1) {
        panic("QEMU platform: unsupported or inconsistent CPU enumeration");
    }
    ums512_cpu_topology_proof.num_cpus=topology->num_cpus;
    ums512_cpu_topology_proof.max_cpu_id=topology->max_cpu_id;
    ums512_cpu_topology_proof.boot_cpu_id=topology->boot_cpu->cpu_id;
    ums512_cpu_topology_proof.boot_phys_id=topology->boot_cpu->phys_id;
    ums512_cpu_topology_proof.current_affinity=affinity;
    ums512_cpu_topology_proof.machine_max_cpus=machine_info.max_cpus;
    ml_set_max_cpus(topology->num_cpus);
    ums512_cpu_topology_proof.published=1;
}
void ums512_gic_send_self_sgi(void)
{
    uint64_t mpidr=__builtin_arm_rsr64("MPIDR_EL1");
    unsigned affinity0=(unsigned)(mpidr&255);
    if (!ums512_irq_proof.initialized || affinity0>15) { panic("UMS512 GIC: unsupported SGI target"); }
    uint64_t target=((mpidr>>32)&255)<<48 | ((mpidr>>16)&255)<<32 |
                    ((mpidr>>8)&255)<<16 | (UINT64_C(1)<<affinity0);
    barrier();
    __builtin_arm_wsr64("ICC_SGI1R_EL1",target);
    __asm__ volatile("isb":::"memory");
}
