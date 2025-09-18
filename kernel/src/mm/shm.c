#include <mm/mm.h>
#include <mm/shm.h>
#include <task/task.h>

shm_t shm_head = {
    .next = NULL,
    .key = 0xffffffff,
    .shmid = 0xffffffff,
    .addr = NULL,
    .size = 0,
    .uid = 0,
    .gid = 0,
};

static int shmid_counter = 1;

uint64_t sys_shmget(int key, int size, int shmflg) {
    shm_t *shm = &shm_head;
    while (shm->next) {
        shm = shm->next;
    }
    if (!shm->next && (shmflg & IPC_CREAT) != 0) {
        shm->next = malloc(sizeof(shm_t));
        shm = shm->next;
        memset(shm, 0, sizeof(shm_t));
        shm->shmid = shmid_counter++;
        shm->addr = NULL;
        shm->key = key;
        shm->size = (size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
        shm->uid = current_task->uid;
        shm->gid = current_task->gid;
        return shm->shmid;
    } else {
        shm = &shm_head;
        while (shm->next) {
            if (shm->key == key) {
                return shm->shmid;
            }
            shm = shm->next;
        }

        return -ENOENT;
    }
}

extern spinlock_t mm_op_lock;

void *sys_shmat(int shmid, void *shmaddr, int shmflg) {
    shm_t *shm = &shm_head;
    while (shm) {
        if (shm->shmid == shmid) {
            break;
        }
        shm = shm->next;
    }

    if (!shm) {
        return (void *)-ENOENT;
    }

    if (!shm->addr) {
        shm->addr = alloc_frames_bytes(shm->size);
        if (!shm->addr) {
            return (void *)-ENOMEM;
        }
    }

    if (!shmaddr) {
        uint64_t page_count = shm->size / DEFAULT_PAGE_SIZE;
        uint64_t idx =
            bitmap_find_range(current_task->mmap_regions, page_count, true);
        if (idx == (uint64_t)-1)
            return (void *)-ENOMEM;
        shmaddr = (void *)((idx * DEFAULT_PAGE_SIZE) + USER_MMAP_START);
    }

    spin_lock(&mm_op_lock);

    if ((uint64_t)shmaddr >= USER_MMAP_START &&
        (uint64_t)shmaddr + shm->size <= USER_MMAP_END) {
        bitmap_set_range(current_task->mmap_regions,
                         ((uint64_t)shmaddr - USER_MMAP_START) /
                             DEFAULT_PAGE_SIZE,
                         ((uint64_t)shmaddr - USER_MMAP_START + shm->size) /
                             DEFAULT_PAGE_SIZE,
                         false);
    }

    map_page_range(
        get_current_page_dir(true), (uint64_t)shmaddr,
        translate_address(get_current_page_dir(false), (uint64_t)shm->addr),
        shm->size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    spin_unlock(&mm_op_lock);

    return shmaddr;
}

uint64_t sys_shmdt(void *shmaddr) { return 0; }

uint64_t sys_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
    shm_t *shm = &shm_head;
    while (shm) {
        if (shm->shmid == shmid) {
            break;
        }
        shm = shm->next;
    }

    if (!shm) {
        return -ENOENT;
    }

    switch (cmd) {
    case IPC_RMID:
        shm_t *shm_s = &shm_head;
        while (shm_s->next) {
            if (shm_s->next == shm) {
                break;
            }
            shm_s = shm_s->next;
        }

        shm_s->next = shm->next;
        free_frames_bytes(shm->addr, shm->size);
        free(shm);
        break;

    case IPC_STAT:
        buf->shm_perm.__ipc_perm_key = shm->key;
        buf->shm_perm.mode = 0700;
        buf->shm_perm.uid = shm->uid;
        buf->shm_perm.gid = shm->gid;
        buf->shm_perm.cuid = current_task->uid;
        buf->shm_perm.cgid = current_task->gid;
        break;

    default:
        printk("shmctl: Unsupported command %d\n", cmd);
        return -ENOSYS;
    }

    return 0;
}
