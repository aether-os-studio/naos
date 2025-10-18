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

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;

    if (!shmaddr) {
        uint64_t start_addr = USER_MMAP_START;
        while (vma_find_intersection(mgr, start_addr, start_addr + shm->size)) {
            start_addr += DEFAULT_PAGE_SIZE;
            if (start_addr > USER_MMAP_END)
                return (void *)-ENOMEM;
        }
        shmaddr = (void *)start_addr;
    }

    map_page_range(
        get_current_page_dir(true), (uint64_t)shmaddr,
        translate_address(get_current_page_dir(false), (uint64_t)shm->addr),
        shm->size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    vma_t *vma = vma_alloc();
    if (!vma) {
        return (void *)-ENOMEM;
    }

    vma->vm_start = (uint64_t)shmaddr;
    vma->vm_end = (uint64_t)shmaddr + shm->size;
    vma->vm_flags = 0;

    vma->vm_type = VMA_TYPE_SHM;
    vma->vm_flags |= VMA_ANON;
    vma->vm_fd = -1;

    if (vma_insert(mgr, vma) != 0) {
        vma_free(vma);
        return (void *)-ENOMEM;
    }

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
