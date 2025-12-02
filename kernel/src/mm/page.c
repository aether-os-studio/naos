#include <mm/mm.h>
#include <mm/page.h>

page_t *page_maps;

extern uint64_t memory_size;

extern void *early_alloc(size_t size);

void page_init() {
    uint64_t page_maps_size = memory_size / DEFAULT_PAGE_SIZE * sizeof(page_t);
    page_maps = early_alloc(page_maps_size);
    if (page_maps)
        memset(page_maps, 0, page_maps_size);
}

page_t *get_page(uint64_t addr) {
    return page_maps ? page_maps + (addr / DEFAULT_PAGE_SIZE) : NULL;
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

void address_ref(uint64_t addr) { page_ref(get_page(addr)); }
void address_unref(uint64_t addr) { page_unref(get_page(addr)); }

bool address_can_free(uint64_t addr) { return page_can_free(get_page(addr)); }
