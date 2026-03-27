#pragma once

#include <libs/klibc.h>
#include <mm/hhdm.h>
#include <mm/buddy.h>
#include <mm/page_table.h>
#include <arch/arch.h>
#include <mm/vma.h>
#include <mm/heap.h>

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *aligned_alloc(size_t alignment, size_t size);
void free(void *ptr);

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
    uint64_t brk_start;
    uint64_t brk_current;
    uint64_t brk_end;
    uint64_t membarrier_private_expedited_seq;
    bool membarrier_private_expedited_registered;
} task_mm_info_t;

void frame_init();

// 分配/释放（高层接口）
uintptr_t alloc_frames(size_t count);
void free_frames(uintptr_t addr, size_t count);
uintptr_t alloc_frames_dma32(size_t count);
void free_frames_dma32(uintptr_t addr, size_t count);
void free_frames_released(uintptr_t addr, size_t count);

static inline uint64_t *task_mm_pgdir(task_mm_info_t *mm) {
    return mm ? (uint64_t *)phys_to_virt(mm->page_table_addr) : NULL;
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

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                    uint64_t size, uint64_t flags);
void map_page_range_unforce(uint64_t *pml4, uint64_t vaddr, uint64_t paddr,
                            uint64_t size, uint64_t flags);
void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size);
uint64_t map_change_attribute(uint64_t *pml4, uint64_t vaddr, uint64_t flags);
uint64_t map_change_attribute_range(uint64_t *pgdir, uint64_t vaddr,
                                    uint64_t len, uint64_t flags);
void map_page_range_mm(task_mm_info_t *mm, uint64_t vaddr, uint64_t paddr,
                       uint64_t size, uint64_t flags);
void map_page_range_unforce_mm(task_mm_info_t *mm, uint64_t vaddr,
                               uint64_t paddr, uint64_t size, uint64_t flags);
void unmap_page_range_mm(task_mm_info_t *mm, uint64_t vaddr, uint64_t size);
uint64_t map_change_attribute_range_mm(task_mm_info_t *mm, uint64_t vaddr,
                                       uint64_t len, uint64_t flags);

typedef struct {
    uintptr_t addr;
    size_t actual_count; // 实际分配的页数
} alloc_result_t;

static inline void *alloc_frames_bytes(uint64_t bytes) {
    uint64_t addr =
        phys_to_virt(alloc_frames((bytes + PAGE_SIZE - 1) / PAGE_SIZE));
    return (void *)addr;
}

static inline void free_frames_bytes(void *ptr, uint64_t bytes) {
    free_frames(virt_to_phys((uint64_t)ptr),
                (bytes + PAGE_SIZE - 1) / PAGE_SIZE);
}

static inline void *alloc_frames_bytes_dma32(uint64_t bytes) {
    uint64_t addr =
        phys_to_virt(alloc_frames_dma32((bytes + PAGE_SIZE - 1) / PAGE_SIZE));
    return (void *)addr;
}

static inline void free_frames_bytes_dma32(void *ptr, uint64_t bytes) {
    free_frames_dma32(virt_to_phys((uint64_t)ptr),
                      (bytes + PAGE_SIZE - 1) / PAGE_SIZE);
}

extern void dcache_clean_range(void *addr, size_t size);
extern void dcache_invalidate_range(void *addr, size_t size);
extern void dcache_flush_range(void *addr, size_t size);

extern void memory_barrier(void);

extern void read_barrier(void);

extern void write_barrier(void);

static inline void dma_wmb(void) { write_barrier(); }

static inline void dma_rmb(void) { read_barrier(); }

static inline void dma_mb(void) { memory_barrier(); }

static inline void dma_sync_cpu_to_device(void *addr, size_t size) {
    dma_wmb();
    dcache_clean_range(addr, size);
}

static inline void dma_sync_device_to_cpu(void *addr, size_t size) {
    dcache_invalidate_range(addr, size);
    dma_rmb();
}

static inline void dma_sync_bidirectional(void *addr, size_t size) {
    dma_mb();
    dcache_flush_range(addr, size);
}
