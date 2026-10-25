#include "platform.h"
#include "facts.h" /* Generated solely from boards/ums512-hardware.json. */

static int valid(struct ums512_extent e) {
    return e.size && e.base <= UINT64_MAX - e.size;
}
static int overlaps(struct ums512_extent a, struct ums512_extent b) {
    return a.base < b.base + b.size && b.base < a.base + a.size;
}
static int inside(struct ums512_extent outer, struct ums512_extent inner) {
    return inner.base >= outer.base && inner.base + inner.size <= outer.base + outer.size;
}
int ums512_validate_plan(const struct ums512_plan *p,
                        const struct ums512_extent *live, size_t n) {
    if (!p || (n && !live) || n > 256) return UMS512_INVALID;
    uint64_t page = p->page_size;
    if (page != 4096 && page != 16384) return UMS512_UNSUPPORTED;
    if (!valid(p->ram) || p->ram.base < UMS512_RAM_BASE ||
        p->ram.base + p->ram.size > UMS512_RAM_END ||
        (p->ram.base | p->ram.size | p->virt_base | p->top) & (page - 1)) return UMS512_RANGE;
    if ((p->virt_base >> 48) != 0xffff || p->virt_base > UINT64_MAX - p->ram.size ||
        p->top < p->ram.base || p->top > p->ram.base + p->ram.size) return UMS512_RANGE;
    /* XNU gets one conservative contiguous window, not the entire DRAM envelope. */
    for (size_t i = 0; i < sizeof(ums512_reserved)/sizeof(ums512_reserved[0]); ++i)
        if (overlaps(p->ram, ums512_reserved[i])) return UMS512_OVERLAP;
    for (size_t i = 0; i < n; ++i) {
        if (!valid(live[i])) return UMS512_RANGE;
        if (overlaps(p->ram, live[i])) return UMS512_OVERLAP;
    }
    const struct ums512_extent regions[] = {p->kernel, p->args, p->adt, p->stack, p->log};
    const uint64_t aligns[] = {page, 8, 4, 16, 8};
    if (p->args.size != sizeof(struct xnu_boot_args) || p->adt.size > UINT32_MAX ||
        p->log.size < sizeof(struct ums512_log) || p->stack.size < page) return UMS512_INVALID;
    for (size_t i = 0; i < 5; ++i) {
        if (!valid(regions[i]) || !inside(p->ram, regions[i]) ||
            regions[i].base % aligns[i] || regions[i].base + regions[i].size > p->top)
            return UMS512_RANGE;
        /* The transfer uses the stack END as SP_EL1, not its aligned base. */
        if (i==3 && (regions[i].base+regions[i].size)%16) return UMS512_RANGE;
        for (size_t j = 0; j < i; ++j)
            if (overlaps(regions[i], regions[j])) return UMS512_OVERLAP;
    }
    return UMS512_OK;
}

int ums512_boot_args(struct xnu_boot_args *out, const struct ums512_plan *p,
                    const struct ums512_extent *live, size_t n, const char *cmd, size_t len) {
    if (!out || !cmd || len >= sizeof(out->command_line)) return UMS512_INVALID;
    for (size_t i = 0; i < len; ++i) if (!cmd[i]) return UMS512_INVALID;
    int result = ums512_validate_plan(p, live, n);
    if (result) return result;
    /* Only fills a caller-owned structure; no copy to a proposed physical address. */
    struct xnu_boot_args b = {0};
    b.revision = 2; b.version = 2;
    b.virt_base = p->virt_base; b.phys_base = p->ram.base;
    b.mem_size = p->ram.size; b.mem_size_actual = p->ram.size;
    b.top_of_kernel_data = p->top;
    /* ARM pe_init.c dereferences deviceTreeP after MMU enable: use the KVA. */
    b.device_tree = p->virt_base + (p->adt.base - p->ram.base);
    b.device_tree_length = (uint32_t)p->adt.size;
    for (size_t i = 0; i < len; ++i) b.command_line[i] = cmd[i];
    *out = b;
    return UMS512_OK;
}

int ums512_gicr_select(uint64_t mpidr, const uint64_t *typers, size_t count, uint64_t *pa) {
    if (!typers || !pa || !count || count > UMS512_GICR_SIZE / UMS512_GICR_STRIDE)
        return UMS512_INVALID;
    uint32_t affinity = (uint32_t)(mpidr & 0xffffff) | (uint32_t)((mpidr >> 8) & 0xff000000);
    size_t found = count;
    for (size_t i = 0; i < count; ++i) {
        /* This physical profile has an explicit 128KiB DT stride. GICv4 VLPI
         * frames need a different layout; do not silently apply that stride. */
        if (typers[i] & 2u) return UMS512_UNSUPPORTED;
        if ((typers[i] >> 32) == affinity) {
            if (found != count) return UMS512_INVALID;
            found = i;
        }
        if (typers[i] & (1u << 4)) {
            if (i + 1 != count) return UMS512_INVALID;
        } else if (i + 1 == count) return UMS512_INVALID;
    }
    if (found == count) return UMS512_NOT_FOUND;
    *pa = UMS512_GICR_BASE + found * UMS512_GICR_STRIDE;
    return UMS512_OK;
}
enum ums512_irq ums512_irq_class(uint64_t iar) {
    uint32_t id = (uint32_t)(iar & 0xffffff);
    if (id >= 1020 && id <= 1023) return UMS512_IRQ_SPURIOUS;
    if (id == UMS512_VTIMER_INTID) return UMS512_IRQ_TIMER;
    return id < 16 ? UMS512_IRQ_SGI : UMS512_IRQ_OTHER;
}
int ums512_timer_ticks(uint64_t ns, uint32_t hz, uint64_t *ticks) {
    if (!ticks || !hz || !ns) return UMS512_INVALID;
    uint64_t sec = ns / 1000000000, rem = ns % 1000000000;
    if (sec > UINT64_MAX / hz) return UMS512_RANGE;
    uint64_t whole = sec * hz;
    uint64_t part = (rem * hz + 999999999) / 1000000000;
    if (whole > UINT64_MAX - part) return UMS512_RANGE;
    *ticks = whole + part;
    return UMS512_OK;
}
int ums512_entry_check(const struct ums512_entry_state *s) {
    if (!s || s->current_el != 4) return UMS512_UNSUPPORTED;
    /* Gate the proposed cold EL1 path; never silently inherit an MMU/cache setup. */
    /* XNU loads boot_args before setting its own SCTLR: reject EE as well. */
    if (s->sctlr & ((1u << 0) | (1u << 2) | (1u << 12) | (1u << 25))) return UMS512_UNSUPPORTED;
    /* 16K granule: accept baseline 1 and LPA2 2; reject absent/unknown. */
    uint64_t granule = (s->mmfr0 >> 20) & 15;
    /* Match XNU's Hz/1e6 divisor and the qualified hardware clock backend. */
    if ((granule != 1 && granule != 2) || s->cntfrq < 1000000 || s->cntfrq > UINT32_MAX)
        return UMS512_UNSUPPORTED;
    return UMS512_OK;
}
int ums512_entry_check_target(const struct ums512_entry_state *s, uint64_t mmfr1,
                             uint64_t midr, uint64_t ctr) {
    int result = ums512_entry_check(s);
    if (result) return result;
    uint64_t part = (midr >> 4) & 0xfff, pa = s->mmfr0 & 15;
    uint64_t pan = (mmfr1 >> 20) & 15;
    if (((midr >> 24) & 255) != 0x41 || (part != 0xd05 && part != 0xd0a) ||
        pa < 2 || pa > 6 || pan < 1 || pan > 3 ||
        (ctr & 15) != 4 || ((ctr >> 16) & 15) != 4) return UMS512_UNSUPPORTED;
    uint64_t affinity = s->mpidr & 0xff00ffffffULL;
    for (size_t i = 0; i < sizeof(ums512_cpu_affinities)/sizeof(ums512_cpu_affinities[0]); ++i)
        if (affinity == ums512_cpu_affinities[i])
            return part == ums512_cpu_parts[i] ? UMS512_OK : UMS512_UNSUPPORTED;
    return UMS512_NOT_FOUND;
}
