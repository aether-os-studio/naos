#include <arch/arch.h>
#include <mm/bitmap.h>
#include <mm/cache.h>
#include <mm/page.h>
#include <mm/tlsf.h>

extern Bitmap usable_regions;
extern uint64_t memory_size;

#define TLSF_FL_INDEX_COUNT 64
#define TLSF_SL_INDEX_LOG2 4
#define TLSF_SL_INDEX_COUNT (1U << TLSF_SL_INDEX_LOG2)

typedef struct tlsf_allocator {
    spinlock_t lock;
    uint64_t fl_bitmap;
    uint32_t sl_bitmap[TLSF_FL_INDEX_COUNT];
    uint64_t free_list[TLSF_FL_INDEX_COUNT][TLSF_SL_INDEX_COUNT];
    uint64_t managed_pages;
    uint64_t free_pages;
} tlsf_allocator_t;

static tlsf_allocator_t tlsf_allocator;

static inline uint64_t phys_to_pfn(uintptr_t phys) { return phys / PAGE_SIZE; }

static inline uintptr_t pfn_to_phys(uint64_t pfn) { return pfn * PAGE_SIZE; }

static inline bool page_is_block_head(const page_t *page) {
    return page && (page->flags & PAGE_FLAG_BLOCK_HEAD);
}

static inline bool page_is_block_tail(const page_t *page) {
    return page && (page->flags & PAGE_FLAG_BLOCK_TAIL);
}

static inline bool page_is_free_head(const page_t *page) {
    return page_is_block_head(page) && (page->flags & PAGE_FLAG_BLOCK_FREE);
}

static inline uint32_t tlsf_msb_index(uint64_t value) {
    return 63U - (uint32_t)__builtin_clzll(value);
}

static inline uint32_t tlsf_lsb_index_u64(uint64_t value) {
    return (uint32_t)__builtin_ctzll(value);
}

static inline uint32_t tlsf_lsb_index_u32(uint32_t value) {
    return (uint32_t)__builtin_ctz(value);
}

static inline void page_meta_clear(page_t *page) {
    if (!page)
        return;

    page->flags = 0;
    page->allocator_state = 0;
    page->span_pages = 0;
    page->allocator_prev_pfn = PAGE_LINK_NONE;
    page->allocator_next_pfn = PAGE_LINK_NONE;
}

static void block_mark(uint64_t pfn, uint32_t pages, bool free) {
    page_t *head = &page_maps[pfn];
    page_t *tail = &page_maps[pfn + pages - 1];

    head->flags = PAGE_FLAG_BLOCK_HEAD | (free ? PAGE_FLAG_BLOCK_FREE : 0);
    if (pages == 1)
        head->flags |= PAGE_FLAG_BLOCK_TAIL;
    head->allocator_state = 0;
    head->span_pages = pages;
    head->allocator_prev_pfn = PAGE_LINK_NONE;
    head->allocator_next_pfn = PAGE_LINK_NONE;

    if (pages == 1)
        return;

    tail->flags = PAGE_FLAG_BLOCK_TAIL;
    tail->allocator_state = 0;
    tail->span_pages = pages;
    tail->allocator_prev_pfn = PAGE_LINK_NONE;
    tail->allocator_next_pfn = PAGE_LINK_NONE;
}

static void tlsf_mapping_insert(size_t pages, uint32_t *fl, uint32_t *sl) {
    if (pages <= 1) {
        *fl = 0;
        *sl = 0;
        return;
    }

    uint32_t first = tlsf_msb_index(pages);
    uint64_t base = 1ULL << first;
    uint64_t step = base >> TLSF_SL_INDEX_LOG2;
    if (step == 0)
        step = 1;

    uint32_t second = (uint32_t)((pages - base) / step);
    if (second >= TLSF_SL_INDEX_COUNT)
        second = TLSF_SL_INDEX_COUNT - 1;

    *fl = first;
    *sl = second;
}

static bool tlsf_mapping_search(size_t pages, uint32_t *fl, uint32_t *sl) {
    if (pages == 0)
        return false;

    if (pages <= 1) {
        *fl = 0;
        *sl = 0;
        return true;
    }

    uint32_t first = tlsf_msb_index(pages);
    uint64_t base = 1ULL << first;
    uint64_t step = base >> TLSF_SL_INDEX_LOG2;
    if (step == 0)
        step = 1;

    uint64_t offset = pages - base;
    uint32_t second = (uint32_t)(offset / step);
    if ((offset % step) != 0)
        second++;

    if (second >= TLSF_SL_INDEX_COUNT) {
        first++;
        second = 0;
    }

    if (first >= TLSF_FL_INDEX_COUNT)
        return false;

    *fl = first;
    *sl = second;
    return true;
}

static void tlsf_insert_free_block_locked(uint64_t pfn) {
    page_t *page = &page_maps[pfn];
    uint32_t fl = 0;
    uint32_t sl = 0;

    ASSERT(page_is_free_head(page));
    ASSERT(page->span_pages != 0);

    tlsf_mapping_insert(page->span_pages, &fl, &sl);

    page->allocator_prev_pfn = PAGE_LINK_NONE;
    page->allocator_next_pfn = tlsf_allocator.free_list[fl][sl];

    if (page->allocator_next_pfn != PAGE_LINK_NONE) {
        page_maps[page->allocator_next_pfn].allocator_prev_pfn = pfn;
    }

    tlsf_allocator.free_list[fl][sl] = pfn;
    tlsf_allocator.sl_bitmap[fl] |= (1U << sl);
    tlsf_allocator.fl_bitmap |= (1ULL << fl);
}

static void tlsf_remove_free_block_locked(uint64_t pfn) {
    page_t *page = &page_maps[pfn];
    uint32_t fl = 0;
    uint32_t sl = 0;

    ASSERT(page_is_free_head(page));
    ASSERT(page->span_pages != 0);

    tlsf_mapping_insert(page->span_pages, &fl, &sl);

    if (page->allocator_prev_pfn != PAGE_LINK_NONE) {
        page_maps[page->allocator_prev_pfn].allocator_next_pfn =
            page->allocator_next_pfn;
    } else {
        tlsf_allocator.free_list[fl][sl] = page->allocator_next_pfn;
    }

    if (page->allocator_next_pfn != PAGE_LINK_NONE) {
        page_maps[page->allocator_next_pfn].allocator_prev_pfn =
            page->allocator_prev_pfn;
    }

    if (tlsf_allocator.free_list[fl][sl] == PAGE_LINK_NONE) {
        tlsf_allocator.sl_bitmap[fl] &= ~(1U << sl);
        if (tlsf_allocator.sl_bitmap[fl] == 0)
            tlsf_allocator.fl_bitmap &= ~(1ULL << fl);
    }

    page->allocator_prev_pfn = PAGE_LINK_NONE;
    page->allocator_next_pfn = PAGE_LINK_NONE;
}

static uint64_t tlsf_find_suitable_block_locked(size_t pages) {
    uint32_t fl = 0;
    uint32_t sl = 0;

    if (!tlsf_mapping_search(pages, &fl, &sl))
        return PAGE_LINK_NONE;

    uint32_t sl_map = tlsf_allocator.sl_bitmap[fl] & (~0U << sl);

    if (sl_map == 0) {
        uint64_t fl_map;

        if (fl + 1 >= TLSF_FL_INDEX_COUNT)
            return PAGE_LINK_NONE;

        fl_map = tlsf_allocator.fl_bitmap & (~0ULL << (fl + 1));
        if (fl_map == 0)
            return PAGE_LINK_NONE;

        fl = tlsf_lsb_index_u64(fl_map);
        sl_map = tlsf_allocator.sl_bitmap[fl];
    }

    sl = tlsf_lsb_index_u32(sl_map);
    return tlsf_allocator.free_list[fl][sl];
}

static bool tlsf_can_coalesce_prev(uint64_t pfn, uint64_t *prev_pfn,
                                   uint32_t *prev_pages) {
    if (pfn == 0)
        return false;

    page_t *tail = &page_maps[pfn - 1];
    if (!page_is_block_tail(tail) || tail->span_pages == 0 ||
        tail->span_pages > pfn) {
        return false;
    }

    uint64_t head_pfn = pfn - tail->span_pages;
    page_t *head = &page_maps[head_pfn];
    if (!page_is_free_head(head) || head->span_pages != tail->span_pages)
        return false;

    *prev_pfn = head_pfn;
    *prev_pages = head->span_pages;
    return true;
}

static bool tlsf_can_coalesce_next(uint64_t pfn, uint32_t pages,
                                   uint64_t *next_pfn, uint32_t *next_pages) {
    uint64_t head_pfn = pfn + pages;
    uint64_t max_pages = memory_size / PAGE_SIZE;

    if (head_pfn >= max_pages)
        return false;

    page_t *head = &page_maps[head_pfn];
    if (!page_is_free_head(head) || head->span_pages == 0)
        return false;

    *next_pfn = head_pfn;
    *next_pages = head->span_pages;
    return true;
}

static uintptr_t tlsf_alloc_pages_locked(size_t count) {
    uint64_t block_pfn = tlsf_find_suitable_block_locked(count);
    if (block_pfn == PAGE_LINK_NONE)
        return 0;

    page_t *block = &page_maps[block_pfn];
    uint32_t block_pages = block->span_pages;

    tlsf_remove_free_block_locked(block_pfn);

    if (block_pages > count) {
        uint64_t remaining_pfn = block_pfn + count;
        uint32_t remaining_pages = block_pages - (uint32_t)count;

        block_mark(block_pfn, (uint32_t)count, false);
        block_mark(remaining_pfn, remaining_pages, true);
        tlsf_insert_free_block_locked(remaining_pfn);
    } else {
        block_mark(block_pfn, block_pages, false);
    }

    tlsf_allocator.free_pages -= count;
    return pfn_to_phys(block_pfn);
}

void tlsf_init(void) {
    memset(&tlsf_allocator, 0, sizeof(tlsf_allocator));
    spin_init(&tlsf_allocator.lock);

    for (size_t fl = 0; fl < TLSF_FL_INDEX_COUNT; fl++) {
        for (size_t sl = 0; sl < TLSF_SL_INDEX_COUNT; sl++)
            tlsf_allocator.free_list[fl][sl] = PAGE_LINK_NONE;
    }
}

void tlsf_add_region(uintptr_t start, uintptr_t end) {
    start = PADDING_UP(start, PAGE_SIZE);
    end = PADDING_DOWN(end, PAGE_SIZE);

    if (start >= end)
        return;

    uint64_t start_pfn = phys_to_pfn(start);
    uint64_t pages = (end - start) / PAGE_SIZE;

    spin_lock(&tlsf_allocator.lock);

    while (pages != 0) {
        uint32_t chunk_pages =
            (pages > UINT32_MAX) ? UINT32_MAX : (uint32_t)pages;
        block_mark(start_pfn, chunk_pages, true);
        tlsf_insert_free_block_locked(start_pfn);

        tlsf_allocator.managed_pages += chunk_pages;
        tlsf_allocator.free_pages += chunk_pages;

        start_pfn += chunk_pages;
        pages -= chunk_pages;
    }

    spin_unlock(&tlsf_allocator.lock);
}

uint64_t tlsf_managed_pages(void) {
    uint64_t managed_pages;

    spin_lock(&tlsf_allocator.lock);
    managed_pages = tlsf_allocator.managed_pages;
    spin_unlock(&tlsf_allocator.lock);

    return managed_pages;
}

uint64_t tlsf_free_pages(void) {
    uint64_t free_pages;

    spin_lock(&tlsf_allocator.lock);
    free_pages = tlsf_allocator.free_pages;
    spin_unlock(&tlsf_allocator.lock);

    return free_pages;
}

static bool claim_last_page_refs(uintptr_t addr, size_t pages) {
    for (size_t offset = 0; offset < pages; offset++) {
        page_t *page = get_page(addr + offset * PAGE_SIZE);
        if (page && page_try_release_last(page))
            continue;

        for (size_t rollback = 0; rollback < offset; rollback++)
            page_ref(get_page(addr + rollback * PAGE_SIZE));
        return false;
    }

    return true;
}

static bool pages_are_unreferenced(uintptr_t addr, size_t pages) {
    for (size_t offset = 0; offset < pages; offset++) {
        page_t *page = get_page(addr + offset * PAGE_SIZE);
        if (!page || page_refcount_read(page) != 0)
            return false;
    }

    return true;
}

static size_t mark_releasable_pages(uintptr_t addr, size_t pages,
                                    bool refs_already_released) {
    size_t releasable_pages = 0;

    for (size_t offset = 0; offset < pages; offset++) {
        page_t *page = get_page(addr + offset * PAGE_SIZE);
        bool releasable = false;

        if (page) {
            releasable = refs_already_released ? page_refcount_read(page) == 0
                                               : page_try_release_last(page);
            page->allocator_state = releasable ? 1 : 0;
        }

        if (releasable)
            releasable_pages++;
    }

    return releasable_pages;
}

static void clear_page_release_marks(uint64_t pfn, uint32_t pages) {
    for (uint32_t offset = 0; offset < pages; offset++) {
        page_maps[pfn + offset].allocator_state = 0;
    }
}

static void tlsf_release_block_locked(uint64_t pfn, uint32_t pages) {
    uint64_t merged_pfn = pfn;
    uint32_t merged_pages = pages;
    uint64_t prev_pfn = 0;
    uint64_t next_pfn = 0;
    uint32_t prev_pages = 0;
    uint32_t next_pages = 0;

    if (tlsf_can_coalesce_prev(merged_pfn, &prev_pfn, &prev_pages)) {
        tlsf_remove_free_block_locked(prev_pfn);
        page_meta_clear(&page_maps[merged_pfn]);
        page_meta_clear(&page_maps[merged_pfn - 1]);
        merged_pfn = prev_pfn;
        merged_pages += prev_pages;
    }

    if (tlsf_can_coalesce_next(merged_pfn, merged_pages, &next_pfn,
                               &next_pages)) {
        tlsf_remove_free_block_locked(next_pfn);
        page_meta_clear(&page_maps[merged_pfn + merged_pages - 1]);
        page_meta_clear(&page_maps[next_pfn]);
        merged_pages += next_pages;
    }

    block_mark(merged_pfn, merged_pages, true);
    tlsf_insert_free_block_locked(merged_pfn);
    tlsf_allocator.free_pages += pages;
}

static void tlsf_release_partial_block(uint64_t pfn, uint32_t pages) {
    uint32_t offset = 0;

    while (offset < pages) {
        bool releasable = page_maps[pfn + offset].allocator_state != 0;
        uint32_t run_pages = 1;

        while (offset + run_pages < pages &&
               (page_maps[pfn + offset + run_pages].allocator_state != 0) ==
                   releasable) {
            run_pages++;
        }

        block_mark(pfn + offset, run_pages, false);
        if (releasable)
            tlsf_release_block_locked(pfn + offset, run_pages);

        offset += run_pages;
    }

    clear_page_release_marks(pfn, pages);
}

uintptr_t alloc_frames(size_t count) {
    if (count == 0 || count > UINT32_MAX)
        return 0;

    uintptr_t addr = 0;

    for (int attempt = 0; attempt < 2; attempt++) {
        spin_lock(&tlsf_allocator.lock);
        if (tlsf_allocator.free_pages >= count)
            addr = tlsf_alloc_pages_locked(count);
        spin_unlock(&tlsf_allocator.lock);

        if (addr != 0)
            break;

        if (attempt == 0) {
            if (cache_reclaim_pages(count * 32) != 0)
                continue;
        }
    }

    if (addr == 0)
        ASSERT(!"Out of memory\n");

    for (size_t offset = 0; offset < count; offset++) {
        page_t *page = get_page(addr + offset * PAGE_SIZE);
        if (page)
            page_ref(page);
    }

    return addr;
}

static void free_frames_common(uintptr_t addr, size_t count,
                               bool refs_already_released) {
    if (addr == 0 || count == 0 || count > UINT32_MAX)
        return;
    if ((addr & (PAGE_SIZE - 1)) != 0)
        return;
    if (addr >= memory_size)
        return;

    uint64_t free_end = addr + count * PAGE_SIZE;
    if (free_end < addr || free_end > memory_size)
        return;

    size_t start_page_index = addr / PAGE_SIZE;
    if (start_page_index + count < start_page_index ||
        start_page_index + count > usable_regions.length) {
        return;
    }

    for (size_t offset = 0; offset < count; offset++) {
        if (!bitmap_get(&usable_regions, start_page_index + offset))
            return;
    }

    uint64_t pfn = phys_to_pfn(addr);
    size_t processed = 0;

    while (processed < count) {
        uint64_t block_pfn = pfn + processed;
        page_t *head = &page_maps[block_pfn];
        if (!page_is_block_head(head) || page_is_free_head(head) ||
            head->span_pages == 0) {
            return;
        }

        uint32_t block_pages = head->span_pages;
        if (processed + block_pages > count)
            return;

        page_t *tail = &page_maps[block_pfn + block_pages - 1];
        if (!page_is_block_tail(tail) || tail->span_pages != block_pages)
            return;

        processed += block_pages;
    }

    processed = 0;
    while (processed < count) {
        uint64_t block_pfn = pfn + processed;
        uint32_t block_pages = page_maps[block_pfn].span_pages;

        size_t releasable_pages = mark_releasable_pages(
            pfn_to_phys(block_pfn), block_pages, refs_already_released);

        if (releasable_pages == 0) {
            clear_page_release_marks(block_pfn, block_pages);
            processed += block_pages;
            continue;
        }

        spin_lock(&tlsf_allocator.lock);
        tlsf_release_partial_block(block_pfn, block_pages);
        spin_unlock(&tlsf_allocator.lock);

        processed += block_pages;
    }
}

void free_frames(uintptr_t addr, size_t count) {
    free_frames_common(addr, count, false);
}

void free_frames_released(uintptr_t addr, size_t count) {
    free_frames_common(addr, count, true);
}
