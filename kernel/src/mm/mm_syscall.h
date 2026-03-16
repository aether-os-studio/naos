#pragma once

#include <mm/mm.h>
#include <mm/shm.h>
#include <fs/vfs/vfs.h>

#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_SHARED_VALIDATE 0x03
#define MAP_TYPE 0x0f
#define MAP_FIXED 0x10
#define MAP_ANON 0x20
#define MAP_ANONYMOUS MAP_ANON
#define MAP_NORESERVE 0x4000
#define MAP_GROWSDOWN 0x0100
#define MAP_DENYWRITE 0x0800
#define MAP_EXECUTABLE 0x1000
#define MAP_LOCKED 0x2000
#define MAP_POPULATE 0x8000
#define MAP_NONBLOCK 0x10000
#define MAP_STACK 0x20000
#define MAP_HUGETLB 0x40000
#define MAP_SYNC 0x80000
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_FILE 0

#define MCL_CURRENT 0x1
#define MCL_FUTURE 0x2

#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define MREMAP_DONTUNMAP 4

#define MADV_NORMAL 0
#define MADV_RANDOM 1
#define MADV_SEQUENTIAL 2
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
#define MADV_FREE 8
#define MADV_REMOVE 9
#define MADV_DONTFORK 10
#define MADV_DOFORK 11
#define MADV_MERGEABLE 12
#define MADV_UNMERGEABLE 13
#define MADV_HUGEPAGE 14
#define MADV_NOHUGEPAGE 15
#define MADV_DONTDUMP 16
#define MADV_DODUMP 17
#define MADV_WIPEONFORK 18
#define MADV_KEEPONFORK 19
#define MADV_COLD 20
#define MADV_PAGEOUT 21
#define MADV_POPULATE_READ 22
#define MADV_POPULATE_WRITE 23

#define MEMBARRIER_CMD_QUERY 0
#define MEMBARRIER_CMD_GLOBAL (1U << 0)
#define MEMBARRIER_CMD_GLOBAL_EXPEDITED (1U << 1)
#define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED (1U << 2)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED (1U << 3)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED (1U << 4)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE (1U << 5)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1U << 6)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ (1U << 7)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ (1U << 8)

#define MPOL_DEFAULT 0
#define MPOL_PREFERRED 1
#define MPOL_BIND 2
#define MPOL_INTERLEAVE 3
#define MPOL_LOCAL 4
#define MPOL_PREFERRED_MANY 5

#define MPOL_F_NODE (1U << 0)
#define MPOL_F_ADDR (1U << 1)
#define MPOL_F_MEMS_ALLOWED (1U << 2)

uint64_t find_unmapped_area(vma_manager_t *mgr, uint64_t hint, uint64_t len);
uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                  uint64_t fd, uint64_t offset);
uint64_t sys_brk(uint64_t brk);
uint64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot);
uint64_t sys_munmap(uint64_t addr, uint64_t size);
uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                    uint64_t flags, uint64_t new_addr);
uint64_t sys_msync(uint64_t addr, uint64_t size, uint64_t flags);
uint64_t sys_mincore(uint64_t addr, uint64_t size, uint64_t vec);
uint64_t sys_madvise(uint64_t addr, uint64_t len, int behavior);
uint64_t sys_mlock(uint64_t addr, uint64_t len);
uint64_t sys_munlock(uint64_t addr, uint64_t len);
uint64_t sys_mlockall(int flags);
uint64_t sys_munlockall(void);
uint64_t sys_membarrier(int cmd, unsigned int flags, int cpu_id);
uint64_t sys_mbind(uint64_t start, uint64_t len, int mode,
                   const unsigned long *nmask, uint64_t maxnode,
                   uint64_t flags);
uint64_t sys_set_mempolicy(int mode, const unsigned long *nmask,
                           uint64_t maxnode);
uint64_t sys_get_mempolicy(int *policy, unsigned long *nmask, uint64_t maxnode,
                           uint64_t addr, uint64_t flags);

void *general_map(fd_t *file, uint64_t addr, uint64_t len, uint64_t prot,
                  uint64_t flags, uint64_t offset);
