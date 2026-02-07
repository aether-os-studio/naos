#pragma once

#include <libs/klibc.h>

typedef struct shm {
    struct shm *next;
    int key;
    int shmid;
    void *addr; /* 物理后备（内核虚拟地址） */
    size_t size;
    uint32_t uid;
    uint32_t gid;
    int nattch;
    bool marked_destroy;
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

uint64_t sys_shmget(int key, int size, int shmflg);
void *sys_shmat(int shmid, void *shmaddr, int shmflg);
uint64_t sys_shmdt(void *shmaddr);
uint64_t sys_shmctl(int shmid, int cmd, struct shmid_ds *buf);

struct task;

void shm_fork(struct task *parent, struct task *child);
void shm_exec(struct task *task);
void shm_exit(struct task *task);
