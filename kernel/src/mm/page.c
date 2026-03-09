#include <mm/mm.h>
#include <mm/bitmap.h>
#include <mm/page.h>

page_t *page_maps;

extern uint64_t memory_size;
extern Bitmap usable_regions;

extern void *early_alloc(size_t size);

void page_init() {
    uint64_t page_maps_size = memory_size / DEFAULT_PAGE_SIZE * sizeof(page_t);
    page_maps = early_alloc(page_maps_size);
    ASSERT(page_maps);
    memset(page_maps, 0, page_maps_size);
}

page_t *get_page(uint64_t addr) {
    return page_maps + (addr / DEFAULT_PAGE_SIZE);
}

void page_ref(page_t *page) {
    if (page)
        page->refcount++;
}
void page_unref(page_t *page) {
    if (page)
        page->refcount--;
}

bool page_can_free(page_t *page) { return page ? page->refcount <= 0 : true; }

void address_ref(uint64_t addr) {
    if (address_is_managed(addr))
        page_ref(get_page(addr));
}
void address_unref(uint64_t addr) {
    if (address_is_managed(addr))
        page_unref(get_page(addr));
}

bool address_can_free(uint64_t addr) {
    return address_is_managed(addr) ? page_can_free(get_page(addr)) : false;
}

bool address_is_managed(uint64_t addr) {
    if (!page_maps || addr >= memory_size)
        return false;

    size_t page_index = addr / DEFAULT_PAGE_SIZE;
    if (page_index >= usable_regions.length)
        return false;

    return bitmap_get(&usable_regions, page_index);
}

void address_release(uint64_t addr) {
    if (!address_is_managed(addr))
        return;

    page_t *page = get_page(addr);
    if (!page || page->refcount <= 0)
        return;

    if (page->refcount > 1) {
        page_unref(page);
        return;
    }

    free_frames(addr, 1);
}
