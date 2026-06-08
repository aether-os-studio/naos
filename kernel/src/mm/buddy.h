#pragma once

#include <libs/klibc.h>
#include <mm/hhdm.h>

#define MAX_ORDER 19
#define ORDER_COUNT MAX_ORDER

typedef struct free_area {
    uint64_t head_pfn;
    uint64_t nr_free;
} free_area_t;

typedef struct buddy_allocator {
    free_area_t free_area[ORDER_COUNT];
    spinlock_t lock;
} buddy_allocator_t;

enum zone_type { ZONE_NORMAL, __MAX_NR_ZONES };

// GFP 标志
#define GFP_DMA (1 << 0)
#define GFP_DMA32 (1 << 1)
#define GFP_KERNEL (1 << 2)
#define GFP_ATOMIC (1 << 3)
#define GFP_NOWAIT (1 << 4)

#define GFP_KERNEL_NORMAL (GFP_KERNEL)
#define GFP_KERNEL_DMA (GFP_KERNEL | GFP_DMA)
#define GFP_KERNEL_DMA32 (GFP_KERNEL | GFP_DMA32)

// Zone 结构
typedef struct zone {
    buddy_allocator_t allocator;
    uint64_t zone_start_pfn;
    uint64_t zone_end_pfn;
    uint64_t managed_pages;
    enum zone_type type;
    const char *name;
} zone_t;

extern zone_t *zones[__MAX_NR_ZONES];
extern int nr_zones;
extern const char *zone_names[__MAX_NR_ZONES];

// 初始化
void buddy_init(void);
void add_memory_region(uintptr_t start, uintptr_t end, enum zone_type type);

// 分配/释放（底层接口）
uintptr_t buddy_alloc_zone(zone_t *zone, size_t count);
uintptr_t buddy_alloc_zone_pages(zone_t *zone, size_t count,
                                 size_t *allocated_pages);
void buddy_free_zone(zone_t *zone, uintptr_t addr, size_t order);
/*
 * Internal allocator handoff only: addr must be an allocator-owned block whose
 * head page was atomically claimed with PAGE_FLAG_FREEING. Normal frame frees
 * must use buddy_free_zone/free_frames so public double-free checks still run.
 */
void buddy_free_zone_claimed(zone_t *zone, uintptr_t addr, size_t order);

// 辅助函数
zone_t *get_zone(enum zone_type type);
bool zone_has_memory(zone_t *zone);
uint64_t zone_free_pages(zone_t *zone);
enum zone_type phys_to_zone_type(uintptr_t phys);
