#pragma once

#include <libs/klibc.h>

typedef struct shm {
    struct shm *next;
    int key;
    int shmid;
    void *addr; /* 物理后备（内核虚拟地址） */
    size_t size;
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    int cpid;
    int lpid;
    long atime;
    long dtime;
    long ctime;
    int nattch;
    bool marked_destroy;
    struct vfs_inode *node;
    char node_name[32];
} shm_t;

typedef struct shm_mapping {
    struct shm_mapping *next;
    shm_t *shm;
    uint64_t uaddr; /* 用户空间虚拟地址 */
} shm_mapping_t;

struct ipc_perm {
    int __ipc_perm_key;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint16_t mode;
    int __ipc_perm_seq;
    long __pad1;
    long __pad2;
};

struct shmid_ds {
    struct ipc_perm shm_perm;
    size_t shm_segsz;
    long shm_atime;
    long shm_dtime;
    long shm_ctime;
    int shm_cpid;
    int shm_lpid;
    uint64_t shm_nattch;
    uint64_t __pad1;
    uint64_t __pad2;
};

#define SHM_RDONLY 010000 /* read-only access */
#define SHM_RND 020000    /* round attach address to SHMLBA boundary */
#define SHM_REMAP 040000  /* take-over region on attach */
#define SHM_EXEC 0100000  /* execution access */

#define IPC_CREAT 01000
#define IPC_EXCL 02000
#define IPC_NOWAIT 04000

#define IPC_RMID 0
#define IPC_SET 1
#define IPC_INFO 3

#define IPC_PRIVATE 0

#define IPC_RMID 0 /* remove resource */
#define IPC_SET 1  /* set ipc_perm options */
#define IPC_STAT 2 /* get ipc_perm options */
#define IPC_INFO 3 /* see ipcs */
#define SHM_LOCK 11
#define SHM_UNLOCK 12
#define SHM_STAT 13
#define SHM_INFO 14

/**
 * Linux contract: create or look up a System V shared memory segment.
 * Current kernel: supports IPC_PRIVATE creation, IPC_CREAT, IPC_EXCL, and
 * segment lookup by key.
 * Gaps: Linux permission checks, sequence-number reuse rules, and global SHM
 * tuning limits are not yet enforced.
 */
uint64_t sys_shmget(int key, int size, int shmflg);
/**
 * Linux contract: attach a System V shared memory segment into the caller's
 * address space.
 * Current kernel: maps the segment into a new shared VMA and honors SHM_RND,
 * SHM_RDONLY, and SHM_EXEC.
 * Gaps: SHM_REMAP replacement semantics and Linux permission enforcement are
 * not implemented, and address selection is driven by the local free-region
 * allocator rather than Linux's full attach heuristics.
 */
void *sys_shmat(int shmid, void *shmaddr, int shmflg);
/**
 * Linux contract: detach a System V shared memory segment from the caller.
 * Current kernel: removes the matching shared-memory VMA and updates nattch.
 * Gaps: detach is keyed by the exact tracked attach address and does not
 * implement Linux's broader attach bookkeeping semantics.
 */
uint64_t sys_shmdt(void *shmaddr);
/**
 * Linux contract: control or query a System V shared memory segment.
 * Current kernel: supports IPC_RMID and IPC_STAT.
 * Gaps: IPC_SET, IPC_INFO, SHM_INFO, and Linux permission/capability rules are
 * still unimplemented and currently fail with -ENOSYS.
 */
uint64_t sys_shmctl(int shmid, int cmd, struct shmid_ds *buf);

struct task;
struct vfs_inode;

typedef struct shm_snapshot_entry {
    int key;
    int shmid;
    uint16_t mode;
    size_t size;
    int cpid;
    int lpid;
    int nattch;
} shm_snapshot_entry_t;

void shm_fork(struct task *parent, struct task *child);
void shm_exec(struct task *task);
void shm_exit(struct task *task);
void shm_try_reap_by_vnode(struct vfs_inode *node);
size_t shm_snapshot(shm_snapshot_entry_t *entries, size_t max_entries);
