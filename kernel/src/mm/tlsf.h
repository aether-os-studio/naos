#pragma once

#include <libs/klibc.h>

void tlsf_init(void);
void tlsf_add_region(uintptr_t start, uintptr_t end);
uintptr_t tlsf_alloc_pages(size_t count);
void tlsf_free_pages_exact(uintptr_t addr, size_t count);

uint64_t tlsf_managed_pages(void);
uint64_t tlsf_free_pages(void);
