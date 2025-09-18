#pragma once

#include <libs/klibc.h>

typedef struct shm {
    struct shm *next;
    int key;
    int shmid;
    void *addr;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
} shm_t;

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

#define IPC_CREAT 00001000
#define IPC_EXCL 00002000
#define IPC_NOWAIT 00004000

uint64_t sys_shmget(int key, int size, int shmflg);
void *sys_shmat(int shmid, void *shmaddr, int shmflg);
uint64_t sys_shmdt(void *shmaddr);

#define IPC_RMID 0 /* remove resource */
#define IPC_SET 1  /* set ipc_perm options */
#define IPC_STAT 2 /* get ipc_perm options */
#define IPC_INFO 3 /* see ipcs */

uint64_t sys_shmctl(int shmid, int cmd, struct shmid_ds *buf);
