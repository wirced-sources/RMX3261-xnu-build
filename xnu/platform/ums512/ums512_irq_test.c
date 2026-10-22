/* SPDX-License-Identifier: MIT. Real XNU timer queue and GIC IRQ test. */
#include <stdint.h>
#include <kern/debug.h>
#include <kern/clock.h>
#include <kern/timer_call.h>
#include <mach/mach_time.h>
#include <machine/machine_routines.h>

struct ums512_timer_proof {
    uint64_t complete,callbacks,interrupt_context,earliest,observed,sgi_sent,reserved0,reserved1;
};
volatile struct ums512_timer_proof ums512_timer_proof;
static timer_call_data_t test_timer;
void ums512_irq_selftest(void);

static void callback(timer_call_param_t p0 __unused,timer_call_param_t p1 __unused)
{
    if (!ml_at_interrupt_context() || ml_get_interrupts_enabled()) {
        panic("UMS512 timer test: callback outside masked interrupt context");
    }
    ums512_timer_proof.observed=mach_absolute_time();
    ums512_timer_proof.interrupt_context=1;
    ums512_timer_proof.callbacks++;
}

void ums512_irq_selftest(void)
{
    if (!ml_get_interrupts_enabled()) { panic("UMS512 timer test: IRQs are masked"); }
    timer_call_setup(&test_timer,callback,NULL);
    for (unsigned trial=0;trial<3;trial++) {
        uint64_t deadline,timeout;
        nanoseconds_to_deadline(2000000,&deadline);
        nanoseconds_to_deadline(2000000000,&timeout);
        ums512_timer_proof.earliest=deadline;
        if (timer_call_enter(&test_timer,deadline,TIMER_CALL_SYS_CRITICAL)) {
            panic("UMS512 timer test: call unexpectedly already queued");
        }
        while (ums512_timer_proof.callbacks<=trial) {
            if (mach_absolute_time()>timeout) { panic("UMS512 timer test: real timer IRQ not delivered"); }
            __asm__ volatile("yield":::"memory");
        }
        if (ums512_timer_proof.observed<deadline) { panic("UMS512 timer test: early callback"); }
    }
    if (timer_call_cancel(&test_timer)) { panic("UMS512 timer test: expired timer remained queued"); }
    ums512_timer_proof.complete=1;
}
