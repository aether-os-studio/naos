#include <arch/arch.h>
#include <mm/buddy.h>
#include <mm/bitmap.h>
#include <mm/cache.h>
#include <mm/page.h>

extern Bitmap usable_regions;

const char *zone_names[__MAX_NR_ZONES] = {"Normal"};

zone_t *zones[__MAX_NR_ZONES] = {NULL};
int nr_zones = 0;

extern uint64_t memory_size;
extern void *early_alloc(size_t size);
#define PCP_HIGH 64

typedef struct per_cpu_pages {
    spinlock_t lock;
    uint64_t head_pfn[__MAX_NR_ZONES];
    uint16_t count[__MAX_NR_ZONES];
} per_cpu_pages_t;

static per_cpu_pages_t per_cpu_pagesets[MAX_CPU_NUM];
static bool percpu_caches_enabled = false;

static inline size_t order_to_index(size_t order) { return order - MIN_ORDER; }

static inline uint64_t order_to_pages(size_t order) {
    return 1ULL << (order - MIN_ORDER);
}

static inline uint64_t order_to_bytes(size_t order) { return 1ULL << order; }

static inline bool order_valid(size_t order) {
    return order >= MIN_ORDER && order < MAX_ORDER;
}

static inline uint64_t phys_to_pfn(uintptr_t phys) { return phys / PAGE_SIZE; }

static inline uintptr_t pfn_to_phys(uint64_t pfn) { return pfn * PAGE_SIZE; }

static inline page_t *page_from_pfn(uint64_t pfn) {
    return (pfn == PAGE_LIST_NONE) ? NULL : &page_maps[pfn];
}

static inline uint64_t page_to_pfn(page_t *page) {
    return (uint64_t)(page - page_maps);
}

static inline uintptr_t zone_phys_start(zone_t *zone) {
    return zone->zone_start_pfn * PAGE_SIZE;
}

static inline uintptr_t zone_phys_end(zone_t *zone) {
    return zone->zone_end_pfn * PAGE_SIZE;
}

static inline bool zone_contains_pfn(zone_t *zone, uint64_t pfn) {
    return zone && pfn >= zone->zone_start_pfn && pfn < zone->zone_end_pfn;
}

static inline void page_detach(page_t *page) {
    page->buddy_prev_pfn = PAGE_LIST_NONE;
    page->buddy_next_pfn = PAGE_LIST_NONE;
}

static inline void page_mark_free(page_t *page, enum zone_type type,
                                  size_t order, uint8_t flag) {
    page->flags = flag;
    page->buddy_order = (uint8_t)order;
    page->zone_id = (uint8_t)type;
    page_detach(page);
}

static inline void page_mark_allocated(page_t *page, enum zone_type type,
                                       size_t order) {
    page->flags = 0;
    page->buddy_order = (uint8_t)order;
    page->zone_id = (uint8_t)type;
    page_detach(page);
}

static inline bool page_is_buddy(page_t *page, size_t order) {
    return page && (page->flags & PAGE_FLAG_BUDDY) &&
           page->buddy_order == order;
}

static bool count_to_order(size_t count, size_t *order_out, size_t *pages_out) {
    if (!order_out || !pages_out || count == 0)
        return false;

    uint64_t pages = 1;
    const uint64_t max_pages = order_to_pages(MAX_ORDER - 1);

    while (pages < count) {
        if (pages > (UINT64_MAX >> 1))
            return false;
        pages <<= 1;
    }

    if (pages > max_pages)
        return false;

    size_t order = MIN_ORDER;
    while ((1ULL << (order - MIN_ORDER)) < pages)
        order++;

    if (!order_valid(order))
        return false;

    *order_out = order;
    *pages_out = (size_t)pages;
    return true;
}

static bool count_to_pages(size_t count, size_t *pages_out) {
    size_t ignored_order = 0;
    return count_to_order(count, &ignored_order, pages_out);
}

static bool zone_block_valid(zone_t *zone, uintptr_t addr, size_t order) {
    if (!zone || !order_valid(order))
        return false;

    const uint64_t block_bytes = order_to_bytes(order);
    const uintptr_t start = zone_phys_start(zone);
    const uintptr_t end = zone_phys_end(zone);
    const uintptr_t block_end = addr + block_bytes;

    if (block_end < addr)
        return false;
    if ((addr & (block_bytes - 1)) != 0)
        return false;
    if (addr < start || block_end > end)
        return false;
    return true;
}

static uint64_t zone_free_pages_locked(zone_t *zone) {
    if (!zone)
        return 0;

    uint64_t free_pages = 0;
    for (size_t index = 0; index < ORDER_COUNT; index++) {
        size_t order = index + MIN_ORDER;
        free_pages +=
            zone->allocator.free_area[index].nr_free * order_to_pages(order);
    }

    return free_pages;
}

static void free_area_add(zone_t *zone, size_t order, page_t *page) {
    const size_t index = order_to_index(order);
    free_area_t *area = &zone->allocator.free_area[index];
    const uint64_t pfn = page_to_pfn(page);

    page_mark_free(page, zone->type, order, PAGE_FLAG_BUDDY);

    if (area->head_pfn != PAGE_LIST_NONE) {
        page_t *head = page_from_pfn(area->head_pfn);
        head->buddy_prev_pfn = pfn;
        page->buddy_next_pfn = area->head_pfn;
    }

    area->head_pfn = pfn;
    area->nr_free++;
}

static void free_area_del(zone_t *zone, size_t order, page_t *page) {
    const size_t index = order_to_index(order);
    free_area_t *area = &zone->allocator.free_area[index];

    if (page->buddy_prev_pfn != PAGE_LIST_NONE) {
        page_t *prev = page_from_pfn(page->buddy_prev_pfn);
        prev->buddy_next_pfn = page->buddy_next_pfn;
    } else {
        area->head_pfn = page->buddy_next_pfn;
    }

    if (page->buddy_next_pfn != PAGE_LIST_NONE) {
        page_t *next = page_from_pfn(page->buddy_next_pfn);
        next->buddy_prev_pfn = page->buddy_prev_pfn;
    }

    if (area->nr_free != 0)
        area->nr_free--;

    page_mark_allocated(page, zone->type, order);
}

static page_t *free_area_pop(zone_t *zone, size_t order) {
    free_area_t *area = &zone->allocator.free_area[order_to_index(order)];

    if (area->head_pfn == PAGE_LIST_NONE)
        return NULL;

    page_t *page = page_from_pfn(area->head_pfn);
    free_area_del(zone, order, page);
    return page;
}

static uintptr_t buddy_alloc_order_locked(zone_t *zone, size_t target_order) {
    size_t order = target_order;
    page_t *page = NULL;

    while (order < MAX_ORDER) {
        page = free_area_pop(zone, order);
        if (page)
            break;
        order++;
    }

    if (!page)
        return 0;

    while (order > target_order) {
        order--;
        const uint64_t right_pfn = page_to_pfn(page) + order_to_pages(order);
        page_t *right = page_from_pfn(right_pfn);
        free_area_add(zone, order, right);
        page_mark_allocated(page, zone->type, order);
    }

    page_mark_allocated(page, zone->type, target_order);
    return pfn_to_phys(page_to_pfn(page));
}

static void buddy_free_order_locked(zone_t *zone, uintptr_t addr,
                                    size_t order) {
    uint64_t pfn = phys_to_pfn(addr);

    while (order < (MAX_ORDER - 1)) {
        const uint64_t buddy_pfn = pfn ^ order_to_pages(order);
        const uintptr_t buddy_phys = pfn_to_phys(buddy_pfn);

        if (!zone_contains_pfn(zone, buddy_pfn))
            break;
        if (!zone_block_valid(zone, buddy_phys, order))
            break;

        page_t *buddy = page_from_pfn(buddy_pfn);
        if (!page_is_buddy(buddy, order))
            break;

        free_area_del(zone, order, buddy);
        if (buddy_pfn < pfn)
            pfn = buddy_pfn;
        order++;
    }

    free_area_add(zone, order, page_from_pfn(pfn));
}

static bool percpu_cache_available(void) {
    return percpu_caches_enabled && current_cpu_id < MAX_CPU_NUM;
}

static uintptr_t percpu_pop(zone_t *zone) {
    if (!percpu_cache_available())
        return 0;

    per_cpu_pages_t *pcp = &per_cpu_pagesets[current_cpu_id];
    uintptr_t phys = 0;

    spin_lock(&pcp->lock);

    uint64_t head_pfn = pcp->head_pfn[zone->type];
    if (head_pfn != PAGE_LIST_NONE) {
        page_t *page = page_from_pfn(head_pfn);
        pcp->head_pfn[zone->type] = page->buddy_next_pfn;
        if (pcp->head_pfn[zone->type] != PAGE_LIST_NONE) {
            page_from_pfn(pcp->head_pfn[zone->type])->buddy_prev_pfn =
                PAGE_LIST_NONE;
        }
        if (pcp->count[zone->type] != 0)
            pcp->count[zone->type]--;
        page_mark_allocated(page, zone->type, MIN_ORDER);
        phys = pfn_to_phys(head_pfn);
    }

    spin_unlock(&pcp->lock);
    return phys;
}

static void percpu_drain_one(zone_t *zone, per_cpu_pages_t *pcp) {
    uint64_t pfn;

    spin_lock(&pcp->lock);
    pfn = pcp->head_pfn[zone->type];
    if (pfn == PAGE_LIST_NONE) {
        spin_unlock(&pcp->lock);
        return;
    }

    page_t *page = page_from_pfn(pfn);
    pcp->head_pfn[zone->type] = page->buddy_next_pfn;
    if (pcp->head_pfn[zone->type] != PAGE_LIST_NONE) {
        page_from_pfn(pcp->head_pfn[zone->type])->buddy_prev_pfn =
            PAGE_LIST_NONE;
    }
    if (pcp->count[zone->type] != 0)
        pcp->count[zone->type]--;
    page_mark_allocated(page, zone->type, MIN_ORDER);
    spin_unlock(&pcp->lock);

    spin_lock(&zone->allocator.lock);
    free_area_add(zone, MIN_ORDER, page);
    spin_unlock(&zone->allocator.lock);
}

static bool percpu_push(zone_t *zone, uintptr_t addr) {
    if (!percpu_cache_available())
        return false;

    per_cpu_pages_t *pcp = &per_cpu_pagesets[current_cpu_id];
    page_t *page = get_page(addr);
    const uint64_t pfn = phys_to_pfn(addr);
    bool need_drain = false;

    spin_lock(&pcp->lock);

    page_mark_free(page, zone->type, MIN_ORDER, PAGE_FLAG_PCPU);
    page->buddy_next_pfn = pcp->head_pfn[zone->type];
    if (pcp->head_pfn[zone->type] != PAGE_LIST_NONE) {
        page_from_pfn(pcp->head_pfn[zone->type])->buddy_prev_pfn = pfn;
    }
    pcp->head_pfn[zone->type] = pfn;
    pcp->count[zone->type]++;
    need_drain = pcp->count[zone->type] > PCP_HIGH;

    spin_unlock(&pcp->lock);

    while (need_drain) {
        percpu_drain_one(zone, pcp);

        spin_lock(&pcp->lock);
        need_drain = pcp->count[zone->type] > PCP_HIGH;
        spin_unlock(&pcp->lock);
    }

    return true;
}

enum zone_type phys_to_zone_type(uintptr_t phys) {
    (void)phys;
    return ZONE_NORMAL;
}

zone_t *get_zone(enum zone_type type) {
    if (type >= __MAX_NR_ZONES)
        return NULL;
    return zones[type];
}

bool zone_has_memory(zone_t *zone) { return zone_free_pages(zone) > 0; }

uint64_t pcpu_cache_free_pages(per_cpu_pages_t *pcp) {
    uint64_t free_pages = 0;
    if (!pcp)
        return 0;

    spin_lock(&pcp->lock);
    for (int zone_id = 0; zone_id < __MAX_NR_ZONES; zone_id++)
        free_pages += pcp->count[zone_id];
    spin_unlock(&pcp->lock);

    return free_pages;
}

uint64_t zone_free_pages(zone_t *zone) {
    uint64_t free_pages = 0;

    if (!zone)
        return 0;

    spin_lock(&zone->allocator.lock);
    free_pages = zone_free_pages_locked(zone);
    spin_unlock(&zone->allocator.lock);

    uint64_t pcp_free_pages = 0;
    for (uint64_t i = 0; i < cpu_count; i++) {
        pcp_free_pages += pcpu_cache_free_pages(&per_cpu_pagesets[i]);
    }

    return free_pages + pcp_free_pages;
}

void buddy_free_zone(zone_t *zone, uintptr_t addr, size_t order) {
    if (!zone_block_valid(zone, addr, order))
        return;

    spin_lock(&zone->allocator.lock);
    buddy_free_order_locked(zone, addr, order);
    spin_unlock(&zone->allocator.lock);
}

uintptr_t buddy_alloc_zone(zone_t *zone, size_t count) {
    if (!zone || count == 0)
        return 0;

    size_t order = 0;
    size_t required_pages = 0;
    if (!count_to_order(count, &order, &required_pages))
        return 0;

    if (required_pages == 1) {
        uintptr_t addr = percpu_pop(zone);
        if (addr != 0)
            return addr;
    }

    spin_lock(&zone->allocator.lock);

    if (zone_free_pages_locked(zone) < required_pages) {
        spin_unlock(&zone->allocator.lock);
        return 0;
    }

    uintptr_t addr = buddy_alloc_order_locked(zone, order);

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

    spin_init(&zone->allocator.lock);

    for (size_t i = 0; i < ORDER_COUNT; i++) {
        zone->allocator.free_area[i].head_pfn = PAGE_LIST_NONE;
        zone->allocator.free_area[i].nr_free = 0;
    }
}

static void create_zone(enum zone_type type, uint64_t start_pfn,
                        uint64_t end_pfn) {
    if (type >= __MAX_NR_ZONES || end_pfn <= start_pfn) {
        zones[type] = NULL;
        return;
    }

    zone_t *zone = (zone_t *)early_alloc(sizeof(zone_t));
    ASSERT(zone != NULL);

    init_zone(zone, type, start_pfn, end_pfn);
    zones[type] = zone;
    nr_zones++;
}

void buddy_init(void) {
    memset(zones, 0, sizeof(zones));
    memset(per_cpu_pagesets, 0, sizeof(per_cpu_pagesets));
    nr_zones = 0;
    percpu_caches_enabled = false;

    for (uint32_t cpu = 0; cpu < MAX_CPU_NUM; cpu++) {
        spin_init(&per_cpu_pagesets[cpu].lock);
        for (size_t zone = 0; zone < __MAX_NR_ZONES; zone++) {
            per_cpu_pagesets[cpu].head_pfn[zone] = PAGE_LIST_NONE;
            per_cpu_pagesets[cpu].count[zone] = 0;
        }
    }

    create_zone(ZONE_NORMAL, 0, memory_size / PAGE_SIZE);
}

void buddy_enable_percpu_caches(void) { percpu_caches_enabled = true; }

static size_t floor_order_for_size(uint64_t bytes) {
    size_t order = MIN_ORDER;
    while (order < MAX_ORDER && (1ULL << order) <= bytes) {
        order++;
    }
    return order - 1;
}

void add_memory_region(uintptr_t start, uintptr_t end, enum zone_type type) {
    zone_t *zone = get_zone(type);
    if (!zone || start >= end)
        return;

    start = PADDING_UP(start, PAGE_SIZE);
    end = PADDING_DOWN(end, PAGE_SIZE);
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
        const uint64_t remaining = end - current;
        const size_t order_by_size = floor_order_for_size(remaining);
        const size_t order_by_align =
            (current == 0)
                ? (MAX_ORDER - 1)
                : MIN((size_t)__builtin_ctzll((unsigned long long)current),
                      (size_t)(MAX_ORDER - 1));

        size_t order = MIN(order_by_size, order_by_align);
        if (order < MIN_ORDER)
            order = MIN_ORDER;

        buddy_free_order_locked(zone, current, order);
        zone->managed_pages += order_to_pages(order);
        current += order_to_bytes(order);
    }

    spin_unlock(&zone->allocator.lock);
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

extern void task_reap_deferred(size_t budget);

uintptr_t alloc_frames(size_t count) {
    if (count == 0)
        return 0;

    size_t required_pages = 0;
    if (!count_to_pages(count, &required_pages))
        return 0;

    uintptr_t addr = 0;
    zone_t *zone = get_zone(ZONE_NORMAL);

    for (int attempt = 0; attempt < 2; attempt++) {
        if (zone) {
            addr = buddy_alloc_zone(zone, count);
            if (addr != 0)
                break;
        }

        if (attempt == 0) {
            if (cache_reclaim_pages(required_pages * 32) != 0)
                continue;
            task_reap_deferred(16);
            continue;
        }
        break;
    }

    if (addr == 0)
        ASSERT(!"No memory can be allocated\n");

    for (size_t offset = 0; offset < required_pages; offset++) {
        page_t *page = get_page(addr + offset * PAGE_SIZE);
        if (page) {
            page_mark_allocated(page, ZONE_NORMAL, MIN_ORDER);
            page_ref(page);
        }
    }

    page_t *head = get_page(addr);
    if (head)
        head->buddy_order =
            (uint8_t)(MIN_ORDER + __builtin_ctzll(required_pages));

    return addr;
}

static void free_frames_common(uintptr_t addr, size_t count,
                               bool refs_already_released) {
    if (addr == 0 || count == 0)
        return;
    if ((addr & (PAGE_SIZE - 1)) != 0)
        return;
    if (addr >= memory_size)
        return;

    size_t required_order = 0;
    size_t required_pages = 0;
    if (!count_to_order(count, &required_order, &required_pages))
        return;

    zone_t *zone = get_zone(ZONE_NORMAL);
    if (!zone)
        return;

    uintptr_t zone_start = zone_phys_start(zone);
    uintptr_t zone_end = zone_phys_end(zone);
    uintptr_t free_end = addr + required_pages * PAGE_SIZE;

    if (free_end < addr || addr < zone_start || free_end > zone_end)
        return;

    size_t start_page_index = addr / PAGE_SIZE;
    if (start_page_index + required_pages < start_page_index ||
        start_page_index + required_pages > usable_regions.length)
        return;

    for (size_t offset = 0; offset < required_pages; offset++) {
        if (!bitmap_get(&usable_regions, start_page_index + offset))
            return;
    }

    if (refs_already_released) {
        if (!pages_are_unreferenced(addr, required_pages))
            return;
    } else {
        if (!claim_last_page_refs(addr, required_pages))
            return;
    }

    page_t *head = get_page(addr);
    if (!head)
        return;
    if (head->flags & (PAGE_FLAG_BUDDY | PAGE_FLAG_PCPU))
        return;

    if (required_pages == 1 && percpu_push(zone, addr)) {
        return;
    }

    spin_lock(&zone->allocator.lock);
    buddy_free_order_locked(zone, addr, required_order);
    spin_unlock(&zone->allocator.lock);
}

void free_frames(uintptr_t addr, size_t count) {
    free_frames_common(addr, count, false);
}

void free_frames_released(uintptr_t addr, size_t count) {
    free_frames_common(addr, count, true);
}
