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
#define MADV_GUARD_INSTALL 102
#define MADV_GUARD_REMOVE 103

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

uint64_t find_unmapped_area(task_mm_info_t *mm, uint64_t hint, uint64_t len);
/**
 * Linux contract: create a new user mapping that follows Linux mmap(2) flag,
 * permission, and file-vs-anonymous rules.
 * Current kernel: supports anonymous mappings and file-backed mappings through
 * the local VMA/VFS layer.
 * Gaps: behavior is only as complete as the backing file's ->mmap callback;
 * unknown flags are tolerated for MAP_PRIVATE/MAP_SHARED but rejected for
 * MAP_SHARED_VALIDATE, and features such as huge pages are only API-level
 * placeholders rather than full Linux implementations.
 */
uint64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                  uint64_t fd, uint64_t offset);
/**
 * Linux contract: grow or shrink the process heap and return the resulting brk.
 * Current kernel: manages a dedicated anonymous heap VMA and returns the old
 * break on failure, matching the Linux userspace ABI.
 */
uint64_t sys_brk(uint64_t brk);
/**
 * Linux contract: change protection bits on an existing mapped range.
 * Current kernel: updates VMA/page-table permissions for covered mappings.
 */
uint64_t sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot);
/**
 * Linux contract: unmap the given address range.
 * Current kernel: removes the covered VMA range and tears down page-table
 * mappings for the calling task.
 */
uint64_t sys_munmap(uint64_t addr, uint64_t size);
/**
 * Linux contract: resize or move an existing mapping while preserving contents
 * according to mremap(2) flags.
 * Current kernel: supports in-place growth/shrink and selected move cases.
 * Gaps: growing shared/device-backed file mappings still depends on the file's
 * ->mmap callback; unsupported backends fail with -ENOSYS.
 */
uint64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                    uint64_t flags, uint64_t new_addr);
/**
 * Linux contract: flush dirty file-backed pages to stable storage.
 * Current kernel: forwards to the backing object when the VFS/file backend
 * exposes sync support and otherwise treats missing sync hooks as a no-op.
 * Gaps: only shared file mappings are written back; anonymous, private, device,
 * and unsupported file mappings effectively succeed without Linux-grade flush
 * semantics.
 */
uint64_t sys_msync(uint64_t addr, uint64_t size, uint64_t flags);
/**
 * Linux contract: report page residency for the supplied mapping.
 * Current kernel: walks the local VMA/page tables and fills the user vector
 * with `1` for mapped pages and `0` otherwise.
 * Gaps: the returned residency bytes do not expose richer Linux mincore()
 * state beyond this mapped/not-mapped distinction.
 */
uint64_t sys_mincore(uint64_t addr, uint64_t size, uint64_t vec);
/**
 * Linux contract: apply advisory memory-management hints to a range.
 * Current kernel: implements populate, dontneed, free-as-dontneed, and guard
 * operations; many other advice values are accepted as no-ops.
 * Gaps: MADV_FREE is stricter than Linux, and MADV_REMOVE is not implemented.
 */
uint64_t sys_madvise(uint64_t addr, uint64_t len, int behavior);
/**
 * Linux contract: pin the supplied pages in memory.
 * Current kernel: faults the range in and validates coverage, but does not
 * maintain a separate long-term mlock accounting model yet.
 */
uint64_t sys_mlock(uint64_t addr, uint64_t len);
/**
 * Linux contract: undo mlock() for the supplied range.
 * Current kernel: validates the range and returns success without tracking a
 * persistent locked-page state.
 */
uint64_t sys_munlock(uint64_t addr, uint64_t len);
/**
 * Linux contract: lock current and/or future mappings according to flags.
 * Current kernel: validates MCL_CURRENT/MCL_FUTURE and returns success.
 * Gaps: future mappings are not tracked as separately locked yet, and existing
 * mappings are not tagged with persistent mlock state.
 */
uint64_t sys_mlockall(int flags);
/**
 * Linux contract: clear process-wide mlockall state.
 * Current kernel: returns success as a compatibility no-op.
 */
uint64_t sys_munlockall(void);
/**
 * Linux contract: provide Linux membarrier(2) commands for expedited memory
 * ordering between threads sharing an mm.
 * Current kernel: supports QUERY, REGISTER_PRIVATE_EXPEDITED, and
 * PRIVATE_EXPEDITED only.
 * Gaps: global and sync-core variants are not implemented.
 */
uint64_t sys_membarrier(int cmd, unsigned int flags, int cpu_id);
/**
 * Linux contract: install a NUMA policy for a virtual address range.
 * Current kernel: validates arguments and returns success without storing a
 * per-range NUMA policy.
 * Gaps: this is effectively a compatibility stub until real NUMA policy state
 * exists.
 */
uint64_t sys_mbind(uint64_t start, uint64_t len, int mode,
                   const unsigned long *nmask, uint64_t maxnode,
                   uint64_t flags);
/**
 * Linux contract: set the calling task's default NUMA policy.
 * Current kernel: validates the requested mode but does not persist a real
 * NUMA policy yet.
 * Gaps: this is effectively a compatibility stub until real NUMA policy state
 * exists.
 */
uint64_t sys_set_mempolicy(int mode, const unsigned long *nmask,
                           uint64_t maxnode);
/**
 * Linux contract: report the current NUMA policy or allowed node mask.
 * Current kernel: reports a synthetic MPOL_DEFAULT policy and a generated node
 * mask for the supported query flags.
 * Gaps: there is no real NUMA placement state behind the returned values.
 */
uint64_t sys_get_mempolicy(int *policy, unsigned long *nmask, uint64_t maxnode,
                           uint64_t addr, uint64_t flags);

void *general_map(fd_t *file, uint64_t addr, uint64_t len, uint64_t prot,
                  uint64_t flags, uint64_t offset);
