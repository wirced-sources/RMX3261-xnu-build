/* SPDX-License-Identifier: MIT. Actual kernel thread, semaphore and timeout APIs. */
#include <stdint.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <mach/sync_policy.h>
#include <kern/debug.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <machine/machine_routines.h>

struct ums512_scheduler_proof {
    uint64_t complete,worker_entries,different_thread,roundtrips;
    uint64_t timed_out,termination_requested,reserved0,reserved1;
};
volatile struct ums512_scheduler_proof ums512_scheduler_proof;
static semaphore_t request,reply;
static thread_t caller;
static volatile uint64_t value,response;
void ums512_scheduler_selftest(void);

static void worker(void *parameter __unused,wait_result_t result __unused)
{
    ums512_scheduler_proof.worker_entries++;
    if (current_thread()==caller || !ml_get_interrupts_enabled()) {
        panic("UMS512 scheduler test: incorrect worker thread/context");
    }
    ums512_scheduler_proof.different_thread=1;
    for (unsigned trial=0;trial<4;trial++) {
        if (semaphore_timedwait(request,(mach_timespec_t){2,0})!=KERN_SUCCESS) {
            panic("UMS512 scheduler test: request timeout");
        }
        if (value!=(UINT64_C(0x51564d5343484544)^trial)) {
            panic("UMS512 scheduler test: incorrect request");
        }
        response=~value;
        if (trial==3) { ums512_scheduler_proof.termination_requested=1; }
        if (semaphore_signal(reply)!=KERN_SUCCESS) { panic("UMS512 scheduler test: reply signal failed"); }
    }
    thread_terminate_self();
}

void ums512_scheduler_selftest(void)
{
    caller=current_thread();
    if (semaphore_create(kernel_task,&request,SYNC_POLICY_FIFO,0)!=KERN_SUCCESS ||
        semaphore_create(kernel_task,&reply,SYNC_POLICY_FIFO,0)!=KERN_SUCCESS) {
        panic("UMS512 scheduler test: semaphore creation failed");
    }
    thread_t thread=THREAD_NULL;
    if (kernel_thread_start(worker,NULL,&thread)!=KERN_SUCCESS || thread==caller) {
        panic("UMS512 scheduler test: worker creation failed");
    }
    for (unsigned trial=0;trial<4;trial++) {
        value=UINT64_C(0x51564d5343484544)^trial;
        if (semaphore_signal(request)!=KERN_SUCCESS ||
            semaphore_timedwait(reply,(mach_timespec_t){2,0})!=KERN_SUCCESS || response!=~value) {
            panic("UMS512 scheduler test: roundtrip failed");
        }
        ums512_scheduler_proof.roundtrips++;
    }
    /* With no reply pending, the original timed wait must actually expire. */
    if (semaphore_timedwait(reply,(mach_timespec_t){0,5000000})!=KERN_OPERATION_TIMED_OUT) {
        panic("UMS512 scheduler test: timed wait did not expire correctly");
    }
    ums512_scheduler_proof.timed_out=1;
    thread_deallocate(thread); /* Release the creator reference, not the live thread. */
    if (semaphore_destroy(kernel_task,request)!=KERN_SUCCESS ||
        semaphore_destroy(kernel_task,reply)!=KERN_SUCCESS) {
        panic("UMS512 scheduler test: semaphore destruction failed");
    }
    ums512_scheduler_proof.complete=1;
}
