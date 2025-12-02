#pragma once

#include <libs/klibc.h>

typedef struct page {
    int refcount;
    // TODO
} page_t;

extern page_t *page_maps;

void page_init();

page_t *get_page(uint64_t addr);

void page_ref(page_t *page);
void page_unref(page_t *page);
bool page_can_free(page_t *page);

void address_ref(uint64_t addr);
void address_unref(uint64_t addr);
bool address_can_free(uint64_t addr);
