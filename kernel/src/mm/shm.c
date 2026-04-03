#include <mm/mm.h>
#include <mm/mm_syscall.h>
#include <mm/shm.h>
#include <task/task.h>

static shm_t *shm_list = NULL;
static int next_shmid = 1;
static spinlock_t shm_op_lock = SPIN_INIT;

static inline long shm_now_seconds(void) {
    return (long)(nano_time() / 1000000000ULL);
}

#define PAGE_ALIGN_UP(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

static shm_t *shm_find_key_locked(int key) {
    for (shm_t *s = shm_list; s; s = s->next) {
        if (s->key == key)
            return s;
    }
    return NULL;
}

static shm_t *shm_find_id_locked(int shmid) {
    for (shm_t *s = shm_list; s; s = s->next) {
        if (s->shmid == shmid)
            return s;
    }
    return NULL;
}

static void shm_unlink_locked(shm_t *shm) {
    for (shm_t **pp = &shm_list; *pp; pp = &(*pp)->next) {
        if (*pp == shm) {
            *pp = shm->next;
            return;
        }
    }
}

static int shm_ensure_backing_locked(shm_t *shm) {
    if (shm->addr)
        return 0;

    shm->addr = alloc_frames_bytes(shm->size);
    if (!shm->addr)
        return -ENOMEM;
    memset(shm->addr, 0, shm->size);
    return 0;
}

static int shm_create_dev_node_locked(shm_t *shm) {
    if (!shm)
        return -EINVAL;
    snprintf(shm->node_name, sizeof(shm->node_name), "sysv_%d", shm->shmid);
    shm->node = NULL;
    return 0;
}

static void shm_try_free_locked(shm_t *shm) {
    if (!shm)
        return;
    if (!shm->marked_destroy || shm->nattch > 0)
        return;

    shm_unlink_locked(shm);
    shm->node = NULL;

    if (shm->addr)
        free_frames_bytes(shm->addr, shm->size);

    free(shm);
}

static void *find_free_region(vma_manager_t *mgr, size_t size) {
    uint64_t len = PAGE_ALIGN_UP(size);
    uint64_t addr = find_unmapped_area(mgr, 0, len);

    if ((int64_t)addr < 0)
        return NULL;
    return (void *)addr;
}

static shm_mapping_t *mapping_add(task_t *task, shm_t *shm, uint64_t uaddr) {
    shm_mapping_t *m = malloc(sizeof(*m));
    if (!m)
        return NULL;

    m->shm = shm;
    m->uaddr = uaddr;
    m->next = task->shm_ids;
    task->shm_ids = m;
    return m;
}

static shm_mapping_t *mapping_find(task_t *task, uint64_t uaddr) {
    for (shm_mapping_t *m = task->shm_ids; m; m = m->next) {
        if (m->uaddr == uaddr)
            return m;
    }
    return NULL;
}

static void mapping_remove(task_t *task, shm_mapping_t *target) {
    for (shm_mapping_t **pp = &task->shm_ids; *pp; pp = &(*pp)->next) {
        if (*pp == target) {
            *pp = target->next;
            free(target);
            return;
        }
    }
}

static void do_shmdt_one(task_t *task, shm_mapping_t *m) {
    shm_t *shm = m->shm;
    vma_manager_t *mgr = &task->mm->task_vma_mgr;

    vma_t *vma = vma_find(mgr, m->uaddr);
    if (vma && vma->vm_type == VMA_TYPE_SHM && vma->vm_start == m->uaddr) {
        spin_lock(&task->mm->lock);
        unmap_page_range_mm(task->mm, vma->vm_start,
                            vma->vm_end - vma->vm_start);
        spin_unlock(&task->mm->lock);
        vma_remove(mgr, vma);
        vma_free(vma);
    }

    if (shm) {
        if (shm->nattch > 0)
            shm->nattch--;
        shm->dtime = shm_now_seconds();
        shm->lpid = task->pid;
        shm_try_free_locked(shm);
    }
}

void shm_try_reap_by_vnode(struct vfs_inode *node) { (void)node; }

uint64_t sys_shmget(int key, int size, int shmflg) {
    shm_t *shm;

    if (size <= 0)
        return -EINVAL;

    spin_lock(&shm_op_lock);

    if (key != IPC_PRIVATE) {
        shm = shm_find_key_locked(key);
        if (shm) {
            if ((size_t)PAGE_ALIGN_UP((size_t)size) > shm->size) {
                spin_unlock(&shm_op_lock);
                return -EINVAL;
            }
            if (shmflg & IPC_EXCL) {
                spin_unlock(&shm_op_lock);
                return -EEXIST;
            }
            spin_unlock(&shm_op_lock);
            return shm->shmid;
        }
    }

    if (key != IPC_PRIVATE && !(shmflg & IPC_CREAT)) {
        spin_unlock(&shm_op_lock);
        return -ENOENT;
    }

    shm = calloc(1, sizeof(*shm));
    if (!shm) {
        spin_unlock(&shm_op_lock);
        return -ENOMEM;
    }

    shm->shmid = next_shmid++;
    shm->key = key;
    shm->size = PAGE_ALIGN_UP((size_t)size);
    shm->mode = (uint16_t)(shmflg & 0777);
    shm->uid = current_task->uid;
    shm->gid = current_task->gid;
    shm->cuid = current_task->uid;
    shm->cgid = current_task->gid;
    shm->cpid = current_task->pid;
    shm->ctime = shm_now_seconds();

    if (shm_create_dev_node_locked(shm) < 0) {
        free(shm);
        spin_unlock(&shm_op_lock);
        return -ENOMEM;
    }

    shm->next = shm_list;
    shm_list = shm;

    uint64_t shmid = shm->shmid;
    spin_unlock(&shm_op_lock);
    return shmid;
}

void *sys_shmat(int shmid, void *shmaddr, int shmflg) {
    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
    int64_t err = 0;
    shm_t *shm;
    uint64_t addr;
    uint64_t flags;
    uint64_t start;
    uint64_t *pgdir;
    vma_t *vma;

    spin_lock(&mgr->lock);
    spin_lock(&shm_op_lock);

    shm = shm_find_id_locked(shmid);
    if (!shm) {
        err = -EINVAL;
        goto out_unlock;
    }

    err = shm_ensure_backing_locked(shm);
    if (err < 0)
        goto out_unlock;

    if (!shmaddr) {
        shmaddr = find_free_region(mgr, shm->size);
        if (!shmaddr) {
            err = -ENOMEM;
            goto out_unlock;
        }
    }

    addr = (uint64_t)shmaddr;
    if (addr) {
        if (shmflg & SHM_RND) {
            addr = PADDING_DOWN(addr, PAGE_SIZE);
        } else if (addr & (PAGE_SIZE - 1)) {
            err = -EINVAL;
            goto out_unlock;
        }
    }

    if (vma_find_intersection(mgr, addr, addr + shm->size)) {
        err = -EINVAL;
        goto out_unlock;
    }

    flags = PT_FLAG_U | PT_FLAG_R;
    if (!(shmflg & SHM_RDONLY))
        flags |= PT_FLAG_W;
    if (shmflg & SHM_EXEC)
        flags |= PT_FLAG_X;

    start = addr;
    pgdir = get_current_page_dir(false);
    spin_lock(&current_task->mm->lock);
    for (uint64_t ptr = start; ptr < start + shm->size; ptr += PAGE_SIZE) {
        map_page_range_mm(
            current_task->mm, ptr,
            translate_address(pgdir, (uint64_t)shm->addr + ptr - start),
            PAGE_SIZE, flags);
    }
    spin_unlock(&current_task->mm->lock);

    vma = vma_alloc();
    if (!vma) {
        spin_lock(&current_task->mm->lock);
        unmap_page_range_mm(current_task->mm, addr, shm->size);
        spin_unlock(&current_task->mm->lock);
        err = -ENOMEM;
        goto out_unlock;
    }

    vma->vm_start = addr;
    vma->vm_end = addr + shm->size;
    vma->vm_type = VMA_TYPE_SHM;
    vma->vm_flags = VMA_SHARED | VMA_SHM | VMA_READ;
    if (!(shmflg & SHM_RDONLY))
        vma->vm_flags |= VMA_WRITE;
    if (shmflg & SHM_EXEC)
        vma->vm_flags |= VMA_EXEC;
    vma->shm = shm;
    vma->shm_id = shm->shmid;

    if (vma_insert(mgr, vma) != 0) {
        vma_free(vma);
        spin_lock(&current_task->mm->lock);
        unmap_page_range_mm(current_task->mm, addr, shm->size);
        spin_unlock(&current_task->mm->lock);
        err = -ENOMEM;
        goto out_unlock;
    }

    if (!mapping_add(current_task, shm, addr)) {
        vma_remove(mgr, vma);
        vma_free(vma);
        spin_lock(&current_task->mm->lock);
        unmap_page_range_mm(current_task->mm, addr, shm->size);
        spin_unlock(&current_task->mm->lock);
        err = -ENOMEM;
        goto out_unlock;
    }

    shm->nattch++;
    shm->atime = shm_now_seconds();
    shm->lpid = current_task->pid;
    spin_unlock(&shm_op_lock);
    spin_unlock(&mgr->lock);
    return (void *)addr;

out_unlock:
    spin_unlock(&shm_op_lock);
    spin_unlock(&mgr->lock);
    return (void *)(int64_t)err;
}

uint64_t sys_shmdt(void *shmaddr) {
    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
    shm_mapping_t *m;

    if (!shmaddr)
        return -EINVAL;

    spin_lock(&mgr->lock);
    spin_lock(&shm_op_lock);

    m = mapping_find(current_task, (uint64_t)shmaddr);
    if (!m) {
        spin_unlock(&shm_op_lock);
        spin_unlock(&mgr->lock);
        return -EINVAL;
    }

    do_shmdt_one(current_task, m);
    mapping_remove(current_task, m);

    spin_unlock(&shm_op_lock);
    spin_unlock(&mgr->lock);
    return 0;
}

uint64_t sys_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
    shm_t *shm;

    spin_lock(&shm_op_lock);
    shm = shm_find_id_locked(shmid);
    if (!shm) {
        spin_unlock(&shm_op_lock);
        return -EINVAL;
    }

    switch (cmd) {
    case IPC_RMID:
        shm->marked_destroy = true;
        shm->ctime = shm_now_seconds();
        shm_try_free_locked(shm);
        break;
    case IPC_STAT: {
        struct shmid_ds info = {0};
        if (!buf) {
            spin_unlock(&shm_op_lock);
            return -EINVAL;
        }
        info.shm_perm.__ipc_perm_key = shm->key;
        info.shm_perm.mode = shm->mode;
        info.shm_perm.uid = shm->uid;
        info.shm_perm.gid = shm->gid;
        info.shm_perm.cuid = shm->cuid;
        info.shm_perm.cgid = shm->cgid;
        info.shm_segsz = shm->size;
        info.shm_atime = shm->atime;
        info.shm_dtime = shm->dtime;
        info.shm_ctime = shm->ctime;
        info.shm_cpid = shm->cpid;
        info.shm_lpid = shm->lpid;
        info.shm_nattch = shm->nattch;
        spin_unlock(&shm_op_lock);
        if (copy_to_user(buf, &info, sizeof(info)))
            return -EFAULT;
        return 0;
    }
    default:
        spin_unlock(&shm_op_lock);
        return -ENOSYS;
    }

    spin_unlock(&shm_op_lock);
    return 0;
}

void shm_fork(task_t *parent, task_t *child) {
    spin_lock(&shm_op_lock);

    child->shm_ids = NULL;
    for (shm_mapping_t *m = parent->shm_ids; m; m = m->next) {
        shm_mapping_t *cm = malloc(sizeof(*cm));
        if (!cm)
            continue;
        cm->shm = m->shm;
        cm->uaddr = m->uaddr;
        cm->next = child->shm_ids;
        child->shm_ids = cm;
        if (m->shm)
            m->shm->nattch++;
    }

    spin_unlock(&shm_op_lock);
}

void shm_exec(task_t *task) {
    shm_mapping_t *m;

    spin_lock(&shm_op_lock);
    m = task->shm_ids;
    while (m) {
        shm_mapping_t *next = m->next;
        if (m->shm) {
            if (m->shm->nattch > 0)
                m->shm->nattch--;
            shm_try_free_locked(m->shm);
        }
        free(m);
        m = next;
    }
    task->shm_ids = NULL;
    spin_unlock(&shm_op_lock);
}

void shm_exit(task_t *task) {
    vma_manager_t *mgr;
    shm_mapping_t *m;

    if (!task || !task->arch_context || !task->mm)
        return;

    mgr = &task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    spin_lock(&shm_op_lock);

    m = task->shm_ids;
    while (m) {
        shm_mapping_t *next = m->next;
        do_shmdt_one(task, m);
        free(m);
        m = next;
    }
    task->shm_ids = NULL;

    spin_unlock(&shm_op_lock);
    spin_unlock(&mgr->lock);
}
