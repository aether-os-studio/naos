#pragma once

#include <mm/mm.h>
#include <fs/vfs/vfs.h>

#define MAP_PRIVATE 2UL
#define MAP_FIXED 16UL
#define MAP_ANONYMOUS 32UL

#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define MREMAP_DONTUNMAP 4

uint64_t sys_brk(uint64_t addr);
uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset);
uint64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot);
uint64_t sys_munmap(uint64_t addr, uint64_t size);
uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size, uint64_t flags, uint64_t new_addr);
uint64_t sys_mincore(uint64_t addr, uint64_t size, uint64_t vec);

void *general_map(vfs_read_t read_callback, void *file, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t offset);
