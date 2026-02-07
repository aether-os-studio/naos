#include <mm/mm.h>
#include <mm/shm.h>
#include <task/task.h>

static shm_t *shm_list = NULL;
static int next_shmid = 1;

#define PAGE_ALIGN_UP(x)                                                       \
    (((x) + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1))

/* ══════════════════════════════════════════════════════════
 *  内部工具
 * ══════════════════════════════════════════════════════════ */

static shm_t *shm_find_key(int key) {
    for (shm_t *s = shm_list; s; s = s->next)
        if (s->key == key)
            return s;
    return NULL;
}

static shm_t *shm_find_id(int shmid) {
    for (shm_t *s = shm_list; s; s = s->next)
        if (s->shmid == shmid)
            return s;
    return NULL;
}

static void shm_unlink(shm_t *shm) {
    for (shm_t **pp = &shm_list; *pp; pp = &(*pp)->next) {
        if (*pp == shm) {
            *pp = shm->next;
            return;
        }
    }
}

/* 引用归零 + 已标记销毁 → 释放物理后备 + 结构体 */
static void shm_try_free(shm_t *shm) {
    if (shm->nattch > 0 || !shm->marked_destroy)
        return;
    shm_unlink(shm);
    if (shm->addr)
        free_frames_bytes(shm->addr, shm->size);
    free(shm);
}

/* 在用户 mmap 区间找空闲区域 */
static void *find_free_region(vma_manager_t *mgr, size_t size) {
    uint64_t addr = USER_MMAP_START;
    while (addr + size <= USER_MMAP_END) {
        vma_t *conflict = vma_find_intersection(mgr, addr, addr + size);
        if (!conflict)
            return (void *)addr;
        addr = PAGE_ALIGN_UP(conflict->vm_end);
    }
    return NULL;
}

/* ── 进程级挂载记录操作 ── */

static shm_mapping_t *mapping_add(task_t *task, shm_t *shm, uint64_t uaddr) {
    shm_mapping_t *m = malloc(sizeof(shm_mapping_t));
    if (!m)
        return NULL;

    m->shm = shm;
    m->uaddr = uaddr;
    m->next = task->shm_ids;
    task->shm_ids = m;
    return m;
}

static shm_mapping_t *mapping_find(task_t *task, uint64_t uaddr) {
    for (shm_mapping_t *m = task->shm_ids; m; m = m->next)
        if (m->uaddr == uaddr)
            return m;
    return NULL;
}

static void mapping_remove(task_t *task, shm_mapping_t *target) {
    for (shm_mapping_t **pp = (shm_mapping_t **)&task->shm_ids; *pp;
         pp = &(*pp)->next) {
        if (*pp == target) {
            *pp = target->next;
            free(target);
            return;
        }
    }
}

/* 对单个进程执行一次 detach（解除映射 + 移除 VMA + 减引用） */
static void do_shmdt_one(task_t *task, shm_mapping_t *m) {
    shm_t *shm = m->shm;
    vma_manager_t *mgr = &task->arch_context->mm->task_vma_mgr;

    /* 移除 VMA */
    vma_t *vma = vma_find(mgr, m->uaddr);
    if (vma && vma->vm_type == VMA_TYPE_SHM && vma->vm_start == m->uaddr) {
        unmap_page_range(get_current_page_dir(true), vma->vm_start,
                         vma->vm_end - vma->vm_start);
        vma_remove(mgr, vma);
        vma_free(vma);
    }

    /* 更新引用计数 */
    if (shm) {
        shm->nattch--;
        shm_try_free(shm);
    }
}

/* ══════════════════════════════════════════════════════════
 *  系统调用
 * ══════════════════════════════════════════════════════════ */

uint64_t sys_shmget(int key, int size, int shmflg) {
    if (key != IPC_PRIVATE) {
        shm_t *s = shm_find_key(key);
        if (s) {
            if (shmflg & IPC_EXCL)
                return -EEXIST;
            return s->shmid;
        }
    }

    if (!(shmflg & IPC_CREAT))
        return -ENOENT;

    shm_t *shm = malloc(sizeof(shm_t));
    if (!shm)
        return -ENOMEM;

    *shm = (shm_t){
        .next = shm_list,
        .shmid = next_shmid++,
        .key = key,
        .size = PAGE_ALIGN_UP(size),
        .uid = current_task->uid,
        .gid = current_task->gid,
        .addr = NULL,
        .nattch = 0,
        .marked_destroy = false,
    };
    shm_list = shm;

    return shm->shmid;
}

void *sys_shmat(int shmid, void *shmaddr, int shmflg) {
    shm_t *shm = shm_find_id(shmid);
    if (!shm || shm->marked_destroy)
        return (void *)(int64_t)-EINVAL;

    /* 延迟分配物理后备 */
    if (!shm->addr) {
        shm->addr = alloc_frames_bytes(shm->size);
        if (!shm->addr)
            return (void *)(int64_t)-ENOMEM;
        memset(shm->addr, 0, shm->size);
    }

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;

    if (!shmaddr) {
        shmaddr = find_free_region(mgr, shm->size);
        if (!shmaddr)
            return (void *)(int64_t)-ENOMEM;
    }

    /* 映射到用户页表 */
    uint64_t phys =
        translate_address(get_current_page_dir(false), (uint64_t)shm->addr);
    uint64_t flags = PT_FLAG_R | PT_FLAG_U;
    if (!(shmflg & SHM_RDONLY))
        flags |= PT_FLAG_W;

    map_page_range(get_current_page_dir(true), (uint64_t)shmaddr, phys,
                   shm->size, flags);

    /* 注册 VMA */
    vma_t *vma = vma_alloc();
    if (!vma)
        return (void *)(int64_t)-ENOMEM;

    vma->vm_start = (uint64_t)shmaddr;
    vma->vm_end = (uint64_t)shmaddr + shm->size;
    vma->vm_type = VMA_TYPE_SHM;
    vma->vm_flags = VMA_ANON;
    vma->shm = shm;
    vma->shm_id = shm->shmid;
    vma->node = NULL;

    if (vma_insert(mgr, vma)) {
        vma_free(vma);
        return (void *)(int64_t)-ENOMEM;
    }

    /* 记录到进程级列表 */
    if (!mapping_add(current_task, shm, (uint64_t)shmaddr)) {
        vma_remove(mgr, vma);
        vma_free(vma);
        return (void *)(int64_t)-ENOMEM;
    }

    shm->nattch++;
    return shmaddr;
}

uint64_t sys_shmdt(void *shmaddr) {
    if (!shmaddr)
        return -EINVAL;

    shm_mapping_t *m = mapping_find(current_task, (uint64_t)shmaddr);
    if (!m)
        return -EINVAL;

    do_shmdt_one(current_task, m);
    mapping_remove(current_task, m);

    return 0;
}

uint64_t sys_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
    shm_t *shm = shm_find_id(shmid);
    if (!shm)
        return -EINVAL;

    switch (cmd) {
    case IPC_RMID:
        shm->marked_destroy = true;
        shm_try_free(shm);
        break;

    case IPC_STAT:
        if (!buf)
            return -EINVAL;
        buf->shm_perm.__ipc_perm_key = shm->key;
        buf->shm_perm.mode = 0700;
        buf->shm_perm.uid = shm->uid;
        buf->shm_perm.gid = shm->gid;
        buf->shm_perm.cuid = current_task->uid;
        buf->shm_perm.cgid = current_task->gid;
        buf->shm_segsz = shm->size;
        buf->shm_nattch = shm->nattch;
        break;

    default:
        return -ENOSYS;
    }

    return 0;
}

void shm_fork(task_t *parent, task_t *child) {
    child->shm_ids = NULL;

    for (shm_mapping_t *m = parent->shm_ids; m; m = m->next) {
        shm_mapping_t *cm = malloc(sizeof(shm_mapping_t));
        if (!cm)
            continue; /* OOM 时静默跳过，不至于崩 */

        cm->shm = m->shm;
        cm->uaddr = m->uaddr;
        cm->next = child->shm_ids;
        child->shm_ids = cm;

        m->shm->nattch++;
    }
}

void shm_exec(task_t *task) {
    shm_mapping_t *m = task->shm_ids;
    while (m) {
        shm_mapping_t *next = m->next;

        if (m->shm) {
            m->shm->nattch--;
            shm_try_free(m->shm);
        }
        free(m);

        m = next;
    }
    task->shm_ids = NULL;
}

void shm_exit(task_t *task) {
    shm_mapping_t *m = task->shm_ids;
    while (m) {
        shm_mapping_t *next = m->next;

        do_shmdt_one(task, m);
        free(m);

        m = next;
    }
    task->shm_ids = NULL;
}
