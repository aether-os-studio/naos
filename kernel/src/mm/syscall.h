#pragma once

#include <mm/mm.h>

uint64_t sys_brk(uint64_t addr);
uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset);
