/* SPDX-License-Identifier: MIT */
#include "xnu_loader.h"

static int contained(uint64_t base, uint64_t size, uint64_t p, uint64_t n)
{ return p >= base && p-base <= size && n <= size-(p-base); }
static int disjoint(uint64_t a, uint64_t n, uint64_t b, uint64_t m)
{ return a <= UINT64_MAX-n && b <= UINT64_MAX-m && (a+n <= b || b+m <= a); }

int ums512_xnu_validate_load(const struct ums512_load_request *r)
{
    if (!r || !r->file || !r->args || !r->adt || r->qualified != UMS512_LOADER_OWNERSHIP ||
        !r->segment_count || r->segment_count > UMS512_LOADER_MAX_SEGMENTS ||
        !r->file_bytes || (r->entry_pa & 3) || ((uintptr_t)r->args & 7) ||
        r->plan.page_size != 16384) return UMS512_INVALID;
    int result=ums512_validate_plan(&r->plan,r->live,r->live_count);
    if (result) return result;
    /* The complete input request/source/ADT/args must survive ALL copies. */
    const struct ums512_extent source[]={{(uintptr_t)r,sizeof(*r)},
        {(uintptr_t)r->file,r->file_bytes},{(uintptr_t)r->adt,r->plan.adt.size},
        {(uintptr_t)r->args,sizeof(*r->args)},
        {(uintptr_t)r->live,r->live_count*sizeof(*r->live)}};
    for (size_t i=0;i<sizeof(source)/sizeof(source[0]);i++)
        if (source[i].size && !disjoint(r->plan.ram.base,r->plan.ram.size,source[i].base,source[i].size))
            return UMS512_OVERLAP;
    const struct xnu_boot_args *a=r->args;
    if (a->revision!=2 || a->version!=2 || a->phys_base!=r->plan.ram.base ||
        a->virt_base!=r->plan.virt_base || a->mem_size!=r->plan.ram.size ||
        a->mem_size_actual!=a->mem_size || a->top_of_kernel_data!=r->plan.top ||
        a->device_tree_length!=r->plan.adt.size ||
        a->device_tree!=a->virt_base+(r->plan.adt.base-a->phys_base) ||
        a->video.base || a->video.display || a->video.row_bytes || a->video.width ||
        a->video.height || a->video.depth) return UMS512_INVALID;
    unsigned executable_entry=0;
    for (size_t i=0;i<r->segment_count;i++) {
        const struct ums512_load_segment *s=&r->segments[i];
        if (!s->memory_bytes || (s->pa & 0x3fff) || (s->memory_bytes & 0x3fff) ||
            s->file_bytes>s->memory_bytes || s->protection>7 || (s->protection & 6)==6 ||
            !contained(0,r->file_bytes,s->file_offset,s->file_bytes) ||
            !contained(r->plan.kernel.base,r->plan.kernel.size,s->pa,s->memory_bytes))
            return UMS512_RANGE;
        for (size_t j=0;j<i;j++)
            if (!disjoint(s->pa,s->memory_bytes,r->segments[j].pa,r->segments[j].memory_bytes))
                return UMS512_OVERLAP;
        if ((s->protection & 4) && contained(s->pa,s->file_bytes,r->entry_pa,4)) executable_entry++;
    }
    return executable_entry==1 ? UMS512_OK : UMS512_RANGE;
}

#ifndef UMS512_LOADER_HOST_TEST
static void copy(uint64_t pa, const unsigned char *s, uint64_t n)
{
    volatile unsigned char *d=(volatile unsigned char *)(uintptr_t)pa;
    for (uint64_t i=0;i<n;i++) d[i]=s[i]; /* exact tails, no rounded overread */
}
int ums512_xnu_load_and_enter(const struct ums512_load_request *r)
{
    uint64_t el;
    __asm__ volatile("mrs %0, CurrentEL":"=r"(el));
    if (el!=4) return UMS512_UNSUPPORTED;
    struct ums512_entry_state s={.current_el=el};
    uint64_t midr,ctr,mmfr1;
    __asm__ volatile("mrs %0, SCTLR_EL1":"=r"(s.sctlr));
    __asm__ volatile("mrs %0, MPIDR_EL1":"=r"(s.mpidr));
    __asm__ volatile("mrs %0, CNTFRQ_EL0":"=r"(s.cntfrq));
    __asm__ volatile("mrs %0, ID_AA64MMFR0_EL1":"=r"(s.mmfr0));
    __asm__ volatile("mrs %0, ID_AA64MMFR1_EL1":"=r"(mmfr1));
    __asm__ volatile("mrs %0, MIDR_EL1":"=r"(midr));
    __asm__ volatile("mrs %0, CTR_EL0":"=r"(ctr));
    int result=ums512_entry_check_target(&s,mmfr1,midr,ctr);
    if (result) return result;
    result=ums512_xnu_validate_load(r);
    if (result) return result;
    __asm__ volatile("msr DAIFSet, #15":::"memory");
    for (size_t i=0;i<r->segment_count;i++) {
        const struct ums512_load_segment *p=&r->segments[i];
        copy(p->pa,r->file+p->file_offset,p->file_bytes);
        volatile unsigned char *b=(volatile unsigned char *)(uintptr_t)(p->pa+p->file_bytes);
        for (uint64_t j=p->file_bytes;j<p->memory_bytes;j++) *b++=0;
    }
    copy(r->plan.adt.base,r->adt,r->plan.adt.size);
    copy(r->plan.args.base,(const unsigned char *)r->args,sizeof(*r->args));
    extern int ums512_handoff_el1(uint64_t,uint64_t,uint64_t);
    return ums512_handoff_el1(r->entry_pa,r->plan.args.base,r->plan.stack.base+r->plan.stack.size);
}
#endif
