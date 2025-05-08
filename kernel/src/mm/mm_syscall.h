#pragma once

#include <mm/mm.h>

#define MAP_PRIVATE 2UL
#define MAP_FIXED 16UL
#define MAP_ANONYMOUS 32UL

#define MAP_FAILED ((uint64_t)-1)

uint64_t sys_brk(uint64_t addr);
uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset);
