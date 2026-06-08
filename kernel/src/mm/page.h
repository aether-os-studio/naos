#pragma once

#include <libs/klibc.h>

struct kmem_cache;

typedef struct page {
    int refcount;
    uint8_t flags;
    uint8_t order;
    uint8_t zone_id;
    uint8_t reserved;
    uint64_t prev_pfn;
    uint64_t next_pfn;
    struct kmem_cache *slab_cache;
    union {
        void *freelist;
        size_t requested_size;
    };
    uint32_t slab_state;
} page_t;

#define PAGE_FLAG_BUDDY 0x01
#define PAGE_FLAG_SLAB 0x02
#define PAGE_FLAG_LARGE 0x04
#define PAGE_FLAG_PCP 0x08
#define PAGE_FLAG_FREEING 0x10

#define PAGE_LIST_NONE UINT64_MAX

extern page_t *page_maps;
extern uint64_t memory_size;

void page_init();

static inline uint64_t page_to_pfn(const page_t *page) {
    return page ? (uint64_t)(page - page_maps) : PAGE_LIST_NONE;
}

static inline uint64_t page_to_phys(const page_t *page) {
    uint64_t pfn = page_to_pfn(page);
    return pfn == PAGE_LIST_NONE ? UINT64_MAX : pfn * PAGE_SIZE;
}

static inline page_t *phys_to_page(uint64_t phys) {
    if (!page_maps || phys >= memory_size)
        return NULL;
    return &page_maps[phys / PAGE_SIZE];
}

/**
 * Translate an address in managed physical memory to its page metadata entry.
 * Notes: this is for addresses that belong to the page allocator's managed
 * range. MMIO, firmware regions, and other unmanaged addresses do not become
 * valid just because they are numerically aligned.
 */
page_t *get_page_by_addr(uint64_t addr);

/**
 * Read the current page refcount.
 * Notes: this is observability, not a lock. Do not build ownership decisions
 * around a naked refcount read unless the surrounding protocol already makes
 * the result stable enough.
 */
int page_refcount_read(page_t *page);
/**
 * Take one reference on a managed page.
 * Notes: callers should already know the page is live. If that assumption is
 * not guaranteed, page_try_ref() is usually the safer primitive.
 */
void page_ref(page_t *page);
bool page_try_ref(page_t *page);
int page_unref(page_t *page);
bool page_try_release_last(page_t *page);
bool page_can_free(page_t *page);

/*
 * Address-based wrappers around page refcounting.
 * Notes: these are convenient when a caller naturally holds a physical address
 * instead of a page_t pointer. They carry the same managed-memory assumptions
 * as get_page_by_addr().
 */
bool address_ref(uint64_t addr);
void address_unref(uint64_t addr);
bool address_can_free(uint64_t addr);
bool address_is_managed(uint64_t addr);
void address_release(uint64_t addr);
