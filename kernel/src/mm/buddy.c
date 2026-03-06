#include <mm/buddy.h>
#include <mm/bitmap.h>
#include <mm/page.h>

extern Bitmap usable_regions;

Bitmap using_regions;

const char *zone_names[__MAX_NR_ZONES] = {
#if defined(__x86_64__)
    "DMA",
#endif
    "DMA32", "Normal"};

zone_t *zones[__MAX_NR_ZONES] = {NULL};
int nr_zones = 0;

extern uint64_t memory_size;
extern void *early_alloc(size_t size);

typedef struct buddy_block {
    uintptr_t next_phys;
    uintptr_t prev_phys;
} buddy_block_t;

typedef struct page_meta {
    uint8_t flags;
    uint8_t order_tag;
} page_meta_t;

typedef struct zone_state {
    page_meta_t *meta;
    uint64_t page_count;
} zone_state_t;

enum {
    PAGE_META_MANAGED = 1U << 0,
    PAGE_META_FREE = 1U << 1,
};

static zone_state_t zone_states[__MAX_NR_ZONES];

static inline size_t order_to_index(size_t order) { return order - MIN_ORDER; }

static inline uint64_t order_to_pages(size_t order) {
    return 1ULL << (order - MIN_ORDER);
}

static inline uint64_t order_to_bytes(size_t order) { return 1ULL << order; }

static inline uint8_t order_encode(size_t order) {
    return (uint8_t)(order - MIN_ORDER + 1);
}

static inline bool order_valid(size_t order) {
    return order >= MIN_ORDER && order < MAX_ORDER;
}

static inline buddy_block_t *block_node(uintptr_t block_phys) {
    return (buddy_block_t *)phys_to_virt(block_phys);
}

static inline zone_state_t *state_of_zone(zone_t *zone) {
    if (!zone || zone->type >= __MAX_NR_ZONES)
        return NULL;
    return &zone_states[zone->type];
}

static inline uintptr_t zone_phys_start(zone_t *zone) {
    return zone->zone_start_pfn * DEFAULT_PAGE_SIZE;
}

static inline uintptr_t zone_phys_end(zone_t *zone) {
    return zone->zone_end_pfn * DEFAULT_PAGE_SIZE;
}

static inline size_t zone_phys_to_page_index(zone_t *zone, uintptr_t phys) {
    return (size_t)((phys - zone_phys_start(zone)) / DEFAULT_PAGE_SIZE);
}

static inline uintptr_t zone_page_index_to_phys(zone_t *zone,
                                                size_t page_index) {
    return zone_phys_start(zone) + page_index * DEFAULT_PAGE_SIZE;
}

static bool zone_block_valid(zone_t *zone, uintptr_t addr, size_t order) {
    if (!zone || !order_valid(order))
        return false;

    uint64_t block_bytes = order_to_bytes(order);
    uintptr_t start = zone_phys_start(zone);
    uintptr_t end = zone_phys_end(zone);
    uintptr_t block_end = addr + block_bytes;

    if (block_end < addr)
        return false;
    if ((addr & (block_bytes - 1)) != 0)
        return false;
    if (addr < start || block_end > end)
        return false;
    return true;
}

static bool count_to_order(size_t count, size_t *order_out, size_t *pages_out) {
    if (!order_out || !pages_out || count == 0)
        return false;

    size_t pages = 1;
    size_t max_pages = (size_t)order_to_pages(MAX_ORDER - 1);

    while (pages < count) {
        if (pages > (SIZE_MAX >> 1))
            return false;
        pages <<= 1;
    }

    if (pages > max_pages)
        return false;

    size_t order = MIN_ORDER;
    size_t current_pages = pages;
    while (current_pages > 1) {
        current_pages >>= 1;
        order++;
    }

    if (!order_valid(order))
        return false;

    *order_out = order;
    *pages_out = pages;
    return true;
}

static bool count_to_pages(size_t count, size_t *pages_out) {
    size_t ignored_order = 0;
    return count_to_order(count, &ignored_order, pages_out);
}

static void list_push_front(zone_t *zone, size_t order, uintptr_t block_phys) {
    size_t index = order_to_index(order);
    uintptr_t head_phys = zone->allocator.free_area[index];
    buddy_block_t *node = block_node(block_phys);

    node->prev_phys = 0;
    node->next_phys = head_phys;

    if (head_phys != 0)
        block_node(head_phys)->prev_phys = block_phys;

    zone->allocator.free_area[index] = block_phys;
}

static void list_remove(zone_t *zone, size_t order, uintptr_t block_phys) {
    size_t index = order_to_index(order);
    buddy_block_t *node = block_node(block_phys);
    uintptr_t prev_phys = node->prev_phys;
    uintptr_t next_phys = node->next_phys;

    if (prev_phys != 0)
        block_node(prev_phys)->next_phys = next_phys;
    else
        zone->allocator.free_area[index] = next_phys;

    if (next_phys != 0)
        block_node(next_phys)->prev_phys = prev_phys;

    node->next_phys = 0;
    node->prev_phys = 0;
}

static uintptr_t list_pop_front(zone_t *zone, size_t order) {
    size_t index = order_to_index(order);
    uintptr_t head_phys = zone->allocator.free_area[index];
    if (head_phys == 0)
        return 0;
    list_remove(zone, order, head_phys);
    return head_phys;
}

static bool block_is_fully_unmanaged(zone_t *zone, size_t block_page_index,
                                     size_t block_pages) {
    zone_state_t *state = state_of_zone(zone);
    if (!state || !state->meta)
        return false;
    if ((uint64_t)block_page_index + block_pages > state->page_count)
        return false;

    for (size_t offset = 0; offset < block_pages; offset++) {
        if (state->meta[block_page_index + offset].flags & PAGE_META_MANAGED)
            return false;
    }
    return true;
}

static void mark_block_managed(zone_t *zone, size_t block_page_index,
                               size_t block_pages) {
    zone_state_t *state = state_of_zone(zone);
    for (size_t offset = 0; offset < block_pages; offset++) {
        state->meta[block_page_index + offset].flags |= PAGE_META_MANAGED;
        state->meta[block_page_index + offset].order_tag = 0;
    }
}

static uintptr_t buddy_alloc_order_locked(zone_t *zone, size_t target_order) {
    zone_state_t *state = state_of_zone(zone);
    if (!state || !state->meta)
        return 0;

    size_t source_order = target_order;
    uintptr_t block_phys = 0;

    while (source_order < MAX_ORDER) {
        block_phys = list_pop_front(zone, source_order);
        if (block_phys != 0)
            break;
        source_order++;
    }

    if (block_phys == 0)
        return 0;

    size_t block_page_index = zone_phys_to_page_index(zone, block_phys);
    state->meta[block_page_index].flags &= ~PAGE_META_FREE;
    state->meta[block_page_index].order_tag = order_encode(source_order);

    while (source_order > target_order) {
        source_order--;

        uintptr_t right_phys = block_phys + order_to_bytes(source_order);
        size_t left_page_index = zone_phys_to_page_index(zone, block_phys);
        size_t right_page_index = zone_phys_to_page_index(zone, right_phys);

        state->meta[left_page_index].flags |= PAGE_META_MANAGED;
        state->meta[left_page_index].flags &= ~PAGE_META_FREE;
        state->meta[left_page_index].order_tag = order_encode(source_order);

        state->meta[right_page_index].flags |= PAGE_META_MANAGED;
        state->meta[right_page_index].flags |= PAGE_META_FREE;
        state->meta[right_page_index].order_tag = order_encode(source_order);

        list_push_front(zone, source_order, right_phys);
    }

    block_page_index = zone_phys_to_page_index(zone, block_phys);
    state->meta[block_page_index].flags |= PAGE_META_MANAGED;
    state->meta[block_page_index].flags &= ~PAGE_META_FREE;
    state->meta[block_page_index].order_tag = order_encode(target_order);

    return block_phys;
}

enum zone_type phys_to_zone_type(uintptr_t phys) {
#if defined(__x86_64__)
    if (phys < ZONE_DMA_END)
        return ZONE_DMA;
#endif
    if (phys < ZONE_DMA32_END)
        return ZONE_DMA32;
    return ZONE_NORMAL;
}

zone_t *get_zone(enum zone_type type) {
    if (type >= __MAX_NR_ZONES)
        return NULL;
    return zones[type];
}

bool zone_has_memory(zone_t *zone) { return zone && zone->free_pages > 0; }

void buddy_free_zone(zone_t *zone, uintptr_t addr, size_t order) {
    if (!zone_block_valid(zone, addr, order))
        return;

    zone_state_t *state = state_of_zone(zone);
    if (!state || !state->meta)
        return;

    size_t block_pages = (size_t)order_to_pages(order);
    size_t page_index = zone_phys_to_page_index(zone, addr);

    if ((uint64_t)page_index + block_pages > state->page_count)
        return;

    bool is_new_managed =
        block_is_fully_unmanaged(zone, page_index, block_pages);
    page_meta_t *head_meta = &state->meta[page_index];

    if (is_new_managed) {
        mark_block_managed(zone, page_index, block_pages);
    } else {
        for (size_t offset = 0; offset < block_pages; offset++) {
            if ((state->meta[page_index + offset].flags & PAGE_META_MANAGED) ==
                0)
                return;
        }
        if (head_meta->flags & PAGE_META_FREE)
            return;
        if (head_meta->order_tag != order_encode(order))
            return;
    }

    size_t current_order = order;
    size_t current_page_index = page_index;

    head_meta = &state->meta[current_page_index];
    head_meta->flags |= PAGE_META_MANAGED;
    head_meta->flags |= PAGE_META_FREE;
    head_meta->order_tag = order_encode(current_order);

    while (current_order < (MAX_ORDER - 1)) {
        size_t pages_in_order = (size_t)order_to_pages(current_order);
        size_t buddy_page_index = current_page_index ^ pages_in_order;

        if ((uint64_t)buddy_page_index + pages_in_order > state->page_count)
            break;

        page_meta_t *buddy_meta = &state->meta[buddy_page_index];
        if ((buddy_meta->flags & (PAGE_META_MANAGED | PAGE_META_FREE)) !=
            (PAGE_META_MANAGED | PAGE_META_FREE))
            break;
        if (buddy_meta->order_tag != order_encode(current_order))
            break;

        uintptr_t buddy_phys = zone_page_index_to_phys(zone, buddy_page_index);
        list_remove(zone, current_order, buddy_phys);

        buddy_meta->flags &= ~PAGE_META_FREE;
        buddy_meta->order_tag = 0;

        if (buddy_page_index < current_page_index)
            current_page_index = buddy_page_index;

        current_order++;
    }

    uintptr_t merged_phys = zone_page_index_to_phys(zone, current_page_index);
    page_meta_t *merged_meta = &state->meta[current_page_index];
    merged_meta->flags |= PAGE_META_MANAGED;
    merged_meta->flags |= PAGE_META_FREE;
    merged_meta->order_tag = order_encode(current_order);
    list_push_front(zone, current_order, merged_phys);

    zone->free_pages += block_pages;
}

uintptr_t buddy_alloc_zone(zone_t *zone, size_t count) {
    if (!zone || count == 0)
        return 0;

    size_t order = 0;
    size_t required_pages = 0;
    if (!count_to_order(count, &order, &required_pages))
        return 0;

    spin_lock(&zone->allocator.lock);

    if (zone->free_pages < required_pages) {
        spin_unlock(&zone->allocator.lock);
        return 0;
    }

    uintptr_t addr = buddy_alloc_order_locked(zone, order);
    if (addr != 0)
        zone->free_pages -= required_pages;

    spin_unlock(&zone->allocator.lock);
    return addr;
}

static void init_zone(zone_t *zone, enum zone_type type, uint64_t start_pfn,
                      uint64_t end_pfn) {
    memset(zone, 0, sizeof(*zone));

    zone->type = type;
    zone->name = zone_names[type];
    zone->zone_start_pfn = start_pfn;
    zone->zone_end_pfn = end_pfn;
    zone->managed_pages = 0;
    zone->free_pages = 0;

    spin_init(&zone->allocator.lock);
    for (size_t index = 0; index < ORDER_COUNT; index++)
        zone->allocator.free_area[index] = 0;

    zone_state_t *state = &zone_states[type];
    state->page_count = (end_pfn > start_pfn) ? (end_pfn - start_pfn) : 0;
    state->meta = NULL;

    if (state->page_count != 0) {
        size_t meta_bytes = (size_t)state->page_count * sizeof(page_meta_t);
        state->meta = (page_meta_t *)early_alloc(meta_bytes);
    }
}

static void create_zone(enum zone_type type, uint64_t start_pfn,
                        uint64_t end_pfn) {
    if (type >= __MAX_NR_ZONES || end_pfn <= start_pfn) {
        zones[type] = NULL;
        return;
    }

    zone_t *zone = (zone_t *)early_alloc(sizeof(zone_t));
    init_zone(zone, type, start_pfn, end_pfn);
    zones[type] = zone;
    nr_zones++;
}

void buddy_init(void) {
    memset(zones, 0, sizeof(zones));
    memset(zone_states, 0, sizeof(zone_states));
    nr_zones = 0;

    uint64_t max_pfn = memory_size / DEFAULT_PAGE_SIZE;
    uint64_t dma32_end_pfn = MIN(max_pfn, ZONE_DMA32_END / DEFAULT_PAGE_SIZE);

#if defined(__x86_64__)
    uint64_t dma_end_pfn = MIN(max_pfn, ZONE_DMA_END / DEFAULT_PAGE_SIZE);

    create_zone(ZONE_DMA, 0, dma_end_pfn);
    create_zone(ZONE_DMA32, dma_end_pfn, dma32_end_pfn);
    create_zone(ZONE_NORMAL, dma32_end_pfn, max_pfn);
#else
    create_zone(ZONE_DMA32, 0, dma32_end_pfn);
    create_zone(ZONE_NORMAL, dma32_end_pfn, max_pfn);
#endif

    size_t bitmap_bytes = (size_t)((max_pfn + 7) / 8);
    if (bitmap_bytes == 0)
        bitmap_bytes = 1;
    void *bitmap_buffer = early_alloc(bitmap_bytes);
    bitmap_init(&using_regions, (uint8_t *)bitmap_buffer, bitmap_bytes);
}

static size_t floor_order_for_size(uint64_t bytes) {
    size_t order = MIN_ORDER;
    while (order + 1 < MAX_ORDER && (1ULL << (order + 1)) <= bytes)
        order++;
    return order;
}

void add_memory_region(uintptr_t start, uintptr_t end, enum zone_type type) {
    zone_t *zone = get_zone(type);
    if (!zone || start >= end)
        return;

    start = PADDING_UP(start, DEFAULT_PAGE_SIZE);
    end = PADDING_DOWN(end, DEFAULT_PAGE_SIZE);
    if (start >= end)
        return;

    uintptr_t zone_start = zone_phys_start(zone);
    uintptr_t zone_end = zone_phys_end(zone);
    if (start < zone_start)
        start = zone_start;
    if (end > zone_end)
        end = zone_end;
    if (start >= end)
        return;

    spin_lock(&zone->allocator.lock);

    uintptr_t current = start;
    while (current < end) {
        uint64_t remaining = end - current;
        size_t max_by_size_order = floor_order_for_size(remaining);
        size_t max_by_align_order =
            (current == 0) ? (MAX_ORDER - 1)
                           : MIN((size_t)__builtin_ctzl((unsigned long)current),
                                 (size_t)(MAX_ORDER - 1));

        size_t candidate_order = MIN(max_by_size_order, max_by_align_order);
        if (candidate_order < MIN_ORDER)
            candidate_order = MIN_ORDER;

        size_t candidate_pages = (size_t)order_to_pages(candidate_order);
        size_t candidate_page_index = zone_phys_to_page_index(zone, current);

        while (candidate_order > MIN_ORDER &&
               !block_is_fully_unmanaged(zone, candidate_page_index,
                                         candidate_pages)) {
            candidate_order--;
            candidate_pages >>= 1;
        }

        if (!block_is_fully_unmanaged(zone, candidate_page_index,
                                      candidate_pages)) {
            current += DEFAULT_PAGE_SIZE;
            continue;
        }

        buddy_free_zone(zone, current, candidate_order);
        zone->managed_pages += candidate_pages;

        current += (uintptr_t)(candidate_pages * DEFAULT_PAGE_SIZE);
    }

    spin_unlock(&zone->allocator.lock);
}

uintptr_t alloc_frames(size_t count) {
    if (count == 0)
        return 0;

    size_t required_pages = 0;
    if (!count_to_pages(count, &required_pages))
        return 0;

    uintptr_t addr = 0;

    if (zones[ZONE_NORMAL] && zone_has_memory(zones[ZONE_NORMAL])) {
        addr = buddy_alloc_zone(zones[ZONE_NORMAL], count);
        if (addr != 0)
            goto out;
    }

    if (zones[ZONE_DMA32] && zone_has_memory(zones[ZONE_DMA32])) {
        addr = buddy_alloc_zone(zones[ZONE_DMA32], count);
        if (addr != 0)
            goto out;
    }

#if defined(__x86_64__)
    if (zones[ZONE_DMA] && zone_has_memory(zones[ZONE_DMA])) {
        addr = buddy_alloc_zone(zones[ZONE_DMA], count);
        if (addr != 0)
            goto out;
    }
#endif

out:
    if (addr == 0)
        return 0;

    size_t page_index = addr / DEFAULT_PAGE_SIZE;
    bitmap_set_range(&using_regions, page_index, page_index + required_pages,
                     true);

    for (uint64_t offset = 0; offset < required_pages; offset++) {
        page_t *page = get_page(addr + offset * DEFAULT_PAGE_SIZE);
        if (page)
            page_ref(page);
    }

    return addr;
}

void free_frames(uintptr_t addr, size_t count) {
    if (addr == 0 || count == 0)
        return;
    if ((addr & (DEFAULT_PAGE_SIZE - 1)) != 0)
        return;

    size_t required_order = 0;
    size_t required_pages = 0;
    if (!count_to_order(count, &required_order, &required_pages))
        return;

    enum zone_type type = phys_to_zone_type(addr);
    zone_t *zone = get_zone(type);
    if (!zone)
        return;

    uintptr_t zone_start = zone_phys_start(zone);
    uintptr_t zone_end = zone_phys_end(zone);
    uintptr_t free_end = addr + required_pages * DEFAULT_PAGE_SIZE;

    if (free_end < addr || addr < zone_start || free_end > zone_end)
        return;

    size_t start_page_index = addr / DEFAULT_PAGE_SIZE;
    if (start_page_index + required_pages < start_page_index ||
        start_page_index + required_pages > using_regions.length ||
        start_page_index + required_pages > usable_regions.length)
        return;

    spin_lock(&zone->allocator.lock);

    for (size_t offset = 0; offset < required_pages; offset++) {
        if (!bitmap_get(&using_regions, start_page_index + offset)) {
            spin_unlock(&zone->allocator.lock);
            return;
        }
        if (!bitmap_get(&usable_regions, start_page_index + offset)) {
            spin_unlock(&zone->allocator.lock);
            return;
        }
    }

    for (size_t offset = 0; offset < required_pages; offset++) {
        page_t *page = get_page(addr + offset * DEFAULT_PAGE_SIZE);
        if (!page || page->refcount != 1) {
            spin_unlock(&zone->allocator.lock);
            return;
        }
    }

    for (size_t offset = 0; offset < required_pages; offset++) {
        address_unref(addr + offset * DEFAULT_PAGE_SIZE);
    }

    buddy_free_zone(zone, addr, required_order);
    bitmap_set_range(&using_regions, start_page_index,
                     start_page_index + required_pages, false);

    spin_unlock(&zone->allocator.lock);
}

uintptr_t alloc_frames_dma32(size_t count) {
    if (count == 0)
        return 0;

    size_t required_pages = 0;
    if (!count_to_pages(count, &required_pages))
        return 0;

    uintptr_t addr = 0;

    if (zones[ZONE_DMA32] && zone_has_memory(zones[ZONE_DMA32])) {
        addr = buddy_alloc_zone(zones[ZONE_DMA32], count);
        if (addr != 0)
            goto out;
    }

#if defined(__x86_64__)
    if (zones[ZONE_DMA] && zone_has_memory(zones[ZONE_DMA])) {
        addr = buddy_alloc_zone(zones[ZONE_DMA], count);
        if (addr != 0)
            goto out;
    }
#endif

out:
    if (addr == 0)
        return 0;

    size_t page_index = addr / DEFAULT_PAGE_SIZE;
    bitmap_set_range(&using_regions, page_index, page_index + required_pages,
                     true);

    for (size_t offset = 0; offset < required_pages; offset++) {
        page_t *page = get_page(addr + offset * DEFAULT_PAGE_SIZE);
        if (page)
            page_ref(page);
    }

    return addr;
}

void free_frames_dma32(uintptr_t addr, size_t count) {
    free_frames(addr, count);
}
