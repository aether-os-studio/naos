#pragma once

#include <libs/klibc.h>

typedef struct page {
    int refcount;
    uint8_t flags;
    uint8_t buddy_order;
    uint8_t zone_id;
    uint8_t reserved;
    uint64_t buddy_prev_pfn;
    uint64_t buddy_next_pfn;
} page_t;

#define PAGE_FLAG_BUDDY 0x01
#define PAGE_FLAG_PCPU 0x02

#define PAGE_LIST_NONE UINT64_MAX

extern page_t *page_maps;

void page_init();

page_t *get_page(uint64_t addr);

int page_refcount_read(page_t *page);
void page_ref(page_t *page);
bool page_try_ref(page_t *page);
int page_unref(page_t *page);
bool page_try_release_last(page_t *page);
bool page_can_free(page_t *page);

bool address_ref(uint64_t addr);
void address_unref(uint64_t addr);
bool address_can_free(uint64_t addr);
bool address_is_managed(uint64_t addr);
void address_release(uint64_t addr);
