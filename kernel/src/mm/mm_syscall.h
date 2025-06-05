#pragma once

#include <mm/mm.h>
#include <fs/vfs/vfs.h>

#define MAP_PRIVATE 2UL
#define MAP_FIXED 16UL
#define MAP_ANONYMOUS 32UL

uint64_t sys_brk(uint64_t addr);
uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset);

void *general_map(vfs_read_t read_callback, void *file, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t offset);
