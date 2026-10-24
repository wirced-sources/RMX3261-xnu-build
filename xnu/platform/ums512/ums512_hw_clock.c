/* SPDX-License-Identifier: MIT
 * Physical UMS512 PE clock backend. Frequencies are qualified handoff inputs;
 * neither fixed-clock parents nor DVFS tables establish current domain rates.
 */
#if !UMS512_HARDWARE_TARGET
#error Physical clock backend must not enter the QEMU kernel
#endif
#include <string.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <libkern/section_keywords.h>
#include "ums512_hw_backend.h"

static SECURITY_READ_ONLY_LATE(unsigned) clock_ready;

void ums512_hw_read_handoff(struct ums512_hw_handoff *out, uint64_t required)
{
    DTEntry root,chosen;
    const void *p;
    unsigned bytes;
    static const char model[]="rmx3261,ums512";
    if (__builtin_arm_rsr64("CurrentEL")!=4 || (__builtin_arm_rsr64("DAIF")&0xc0)!=0xc0 ||
        SecureDTLookupEntry(NULL,"/",&root)!=kSuccess ||
        SecureDTGetProperty(root,"model",&p,&bytes)!=kSuccess || bytes!=sizeof(model) ||
        memcmp(p,model,sizeof(model)) ||
        SecureDTLookupEntry(NULL,"/chosen",&chosen)!=kSuccess ||
        SecureDTGetProperty(chosen,"ums512,hw-handoff",&p,&bytes)!=kSuccess || bytes!=sizeof(*out))
        panic("UMS512HW: qualified physical handoff missing; M1 NO-GO");
    memcpy(out,p,sizeof(*out)); /* ADT data is only 4-byte aligned. */
    if (ums512_hw_contract_check(out,required,__builtin_arm_rsr64("MPIDR_EL1")))
        panic("UMS512HW: invalid physical handoff contract");
    /* Reading CNTFRQ/ICC_* can itself trap at EL2/EL3. The contract must come
     * from a qualified trusted loader; EL1 cannot discover that policy safely.
     * An ADT assertion is not an authentication/physical measurement mechanism.
     */
}
void ums512_hw_clock_identify(boot_args *args)
{
    struct ums512_hw_handoff h;
    struct ums512_hw_clock_result r;
    if (!args || clock_ready) panic("UMS512HW: invalid clock initialization order");
    ums512_hw_read_handoff(&h,UMS512_HW_CLOCK_REQUIRED);
    __asm__ volatile("isb":::"memory");
    uint64_t cntfrq=__builtin_arm_rsr64("CNTFRQ_EL0");
    if (ums512_hw_clock_check(&h,cntfrq,&r))
        panic("UMS512HW: missing/inconsistent clock observations");
    /* Also require the running CPU's ordinary Apple ADT timebase value to
     * agree. This catches disagreement between the adapter and handoff data.
     */
    DTEntry cpus,cpu;
    OpaqueDTEntryIterator iter;
    const void *p;
    unsigned bytes,running=0;
    if (SecureDTLookupEntry(NULL,"/cpus",&cpus)!=kSuccess ||
        SecureDTInitEntryIterator(cpus,&iter)!=kSuccess) panic("UMS512HW: missing CPU tree");
    while (SecureDTIterateEntries(&iter,&cpu)==kSuccess) {
        if (SecureDTGetProperty(cpu,"state",&p,&bytes)!=kSuccess || bytes!=8 || memcmp(p,"running",8)) continue;
        uint32_t affinity,frequency;
        if (++running!=1 || SecureDTGetProperty(cpu,"reg",&p,&bytes)!=kSuccess || bytes!=4)
            panic("UMS512HW: ambiguous running CPU");
        memcpy(&affinity,p,4);
        if (h.mpidr!=affinity || SecureDTGetProperty(cpu,"timebase-frequency",&p,&bytes)!=kSuccess || bytes!=4)
            panic("UMS512HW: inconsistent CPU/timebase ADT");
        memcpy(&frequency,p,4);
        if (frequency!=r.timebase) panic("UMS512HW: ADT/CNTFRQ mismatch");
    }
    if (running!=1) panic("UMS512HW: no running CPU");
    clock_frequency_info_t c={0};
    c.timebase_frequency_hz=r.timebase; c.dec_clock_rate_hz=r.timebase;
    c.timebase_frequency_num=r.timebase; c.timebase_frequency_den=1;
    c.bus_clock_rate_hz=h.bus.hz; c.bus_clock_rate_num=h.bus.hz; c.bus_clock_rate_den=1;
    c.cpu_clock_rate_hz=h.cpu.hz;
    c.bus_to_cpu_rate_num=r.bus_cpu_num; c.bus_to_cpu_rate_den=r.bus_cpu_den;
    c.bus_to_dec_rate_num=r.bus_dec_num; c.bus_to_dec_rate_den=r.bus_dec_den;
    c.bus_frequency_hz=h.bus.hz; c.bus_frequency_min_hz=h.bus.min_hz; c.bus_frequency_max_hz=h.bus.max_hz;
    c.cpu_frequency_hz=h.cpu.hz; c.cpu_frequency_min_hz=h.cpu.min_hz; c.cpu_frequency_max_hz=h.cpu.max_hz;
    c.mem_frequency_hz=h.memory.hz; c.mem_frequency_min_hz=h.memory.min_hz; c.mem_frequency_max_hz=h.memory.max_hz;
    c.prf_frequency_hz=h.peripheral.hz; c.prf_frequency_min_hz=h.peripheral.min_hz; c.prf_frequency_max_hz=h.peripheral.max_hz;
    c.fix_frequency_hz=h.fixed_hz; /* zero means unknown, serial backend remains absent. */
    gPEClockFrequencyInfo=c; /* Publish only after complete validation. */
    clock_ready=1;
}
