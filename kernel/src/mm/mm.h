#pragma once

#include <libs/klibc.h>
#include <mm/hhdm.h>
#include <mm/buddy.h>
#include <mm/page_table.h>
#include <arch/arch.h>
#include <mm/vma.h>

#define MAX_USABLE_REGIONS_COUNT 128

#define PROT_NONE 0x00
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

#define MM_ACTIVE_CPU_WORDS ((MAX_CPU_NUM + 63) / 64)

typedef struct task_mm_info {
    uint64_t page_table_addr;
    int ref_count;
    spinlock_t lock;
    uint64_t active_cpu_mask[MM_ACTIVE_CPU_WORDS];
    vma_manager_t task_vma_mgr;
    uint64_t mmap_top;
    uint64_t signal_trampoline_start;
    uint64_t pie_base;
    uint64_t interpreter_base;
    uint64_t brk_start;
    uint64_t brk_current;
    uint64_t brk_end;
    uint64_t stack_start;
    uint64_t stack_end;
    uint64_t resident_pages;
    uint64_t membarrier_private_expedited_seq;
    bool membarrier_private_expedited_registered;
} task_mm_info_t;

void frame_init();

uint64_t user_va_limit(void);
uint64_t mm_default_mmap_top(void);
void task_mm_init_aslr(task_mm_info_t *mm);
uint64_t task_mm_mmap_top(task_mm_info_t *mm);
uint64_t task_mm_signal_trampoline_start(task_mm_info_t *mm);
uint64_t task_mm_signal_trampoline_end(task_mm_info_t *mm);
uint64_t task_mm_pie_base(task_mm_info_t *mm);
uint64_t task_mm_interpreter_base(task_mm_info_t *mm);
uint64_t task_mm_stack_start(task_mm_info_t *mm);
uint64_t task_mm_stack_end(task_mm_info_t *mm);

/*
 * High-level frame allocator entry points.
 * Notes: these operate on whole physical pages tracked by the buddy/page layer.
 * They are not interchangeable with malloc()/free(); mixing the two ownership
 * models will usually end in silent corruption rather than an immediate crash.
 */
uintptr_t alloc_frames(size_t count);
void free_frames(uintptr_t addr, size_t count);
void free_frames_released(uintptr_t addr, size_t count);

static inline uint64_t *task_mm_pgdir(task_mm_info_t *mm) {
    return mm ? (uint64_t *)phys_to_virt(mm->page_table_addr) : NULL;
}

static inline uint64_t task_mm_resident_pages(task_mm_info_t *mm) {
    return mm ? __atomic_load_n(&mm->resident_pages, __ATOMIC_RELAXED) : 0;
}

static inline void task_mm_mark_cpu_active(task_mm_info_t *mm,
                                           uint32_t cpu_id) {
    if (!mm || cpu_id >= MAX_CPU_NUM)
        return;

    size_t word = cpu_id / 64;
    uint64_t bit = 1ULL << (cpu_id % 64);
    __atomic_or_fetch(&mm->active_cpu_mask[word], bit, __ATOMIC_RELEASE);
}

static inline void task_mm_mark_cpu_inactive(task_mm_info_t *mm,
                                             uint32_t cpu_id) {
    if (!mm || cpu_id >= MAX_CPU_NUM)
        return;

    size_t word = cpu_id / 64;
    uint64_t bit = 1ULL << (cpu_id % 64);
    __atomic_and_fetch(&mm->active_cpu_mask[word], ~bit, __ATOMIC_RELEASE);
}

bool task_mm_flush_tlb_page(task_mm_info_t *mm, uint64_t vaddr);
bool task_mm_flush_tlb_all(task_mm_info_t *mm);

uint64_t map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                        uint64_t size, uint64_t flags);
uint64_t map_page_range_unforce(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                                uint64_t size, uint64_t flags);
void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size);
uint64_t map_change_attribute(uint64_t *pml4, uint64_t vaddr, uint64_t flags);
uint64_t map_change_attribute_range(uint64_t *pgdir, uint64_t vaddr,
                                    uint64_t len, uint64_t flags);
uint64_t map_page_range_mm(task_mm_info_t *mm, uint64_t vaddr, uint64_t paddr,
                           uint64_t size, uint64_t flags);
uint64_t map_page_range_unforce_mm(task_mm_info_t *mm, uint64_t vaddr,
                                   uint64_t paddr, uint64_t size,
                                   uint64_t flags);
void unmap_page_range_mm(task_mm_info_t *mm, uint64_t vaddr, uint64_t size);
uint64_t map_change_attribute_range_mm(task_mm_info_t *mm, uint64_t vaddr,
                                       uint64_t len, uint64_t flags);

/*
 * Byte-sized wrappers around the frame allocator.
 * Notes: these still allocate and free page-granular backing; the byte count
 * is convenience for callers, not a promise of sub-page accounting precision.
 */
void *alloc_frames_bytes(uint64_t bytes);
void free_frames_bytes(void *ptr, uint64_t bytes);

extern void dcache_clean_range(void *addr, size_t size);
extern void dcache_invalidate_range(void *addr, size_t size);
extern void dcache_flush_range(void *addr, size_t size);
extern void sync_instruction_memory_range(void *addr, size_t size);

extern void memory_barrier(void);

extern void read_barrier(void);

extern void write_barrier(void);

static inline void dma_wmb(void) { write_barrier(); }

static inline void dma_rmb(void) { read_barrier(); }

static inline void dma_mb(void) { memory_barrier(); }

static inline void dma_sync_cpu_to_device(void *addr, size_t size) {
    /*
     * Use before handing CPU-written memory to a DMA device. The barrier alone
     * is not enough on non-coherent systems; cache maintenance is the point.
     */
    dma_wmb();
    dcache_clean_range(addr, size);
}

static inline void dma_sync_device_to_cpu(void *addr, size_t size) {
    /*
     * Use after device DMA into memory and before CPU reads. Skipping the cache
     * invalidation is a common bug that leaves drivers reading stale lines.
     */
    dcache_invalidate_range(addr, size);
    dma_rmb();
}

static inline void dma_sync_bidirectional(void *addr, size_t size) {
    /*
     * Use when ownership can move in both directions or when the safer answer
     * is to flush both ways. This is heavier than one-way sync on purpose.
     */
    dma_mb();
    dcache_flush_range(addr, size);
}
