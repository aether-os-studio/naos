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

struct shminfo {
    uint64_t shmmax;
    uint64_t shmmin;
    uint64_t shmmni;
    uint64_t shmseg;
    uint64_t shmall;
    uint64_t __unused[4];
};

struct shm_info {
    int used_ids;
    uint64_t shm_tot;
    uint64_t shm_rss;
    uint64_t shm_swp;
    uint64_t swap_attempts;
    uint64_t swap_successes;
};

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
    if (!current_task || !current_task->mm)
        return NULL;

    uint64_t len = PAGE_ALIGN_UP(size);
    uint64_t addr = find_unmapped_area(current_task->mm, 0, len);

    if ((int64_t)addr < 0)
        return NULL;
    return (void *)addr;
}

static shm_mapping_t *mapping_find(task_t *task, uint64_t uaddr) {
    for (shm_mapping_t *m = task->shm_ids; m; m = m->next) {
        if (m->uaddr == uaddr)
            return m;
    }
    return NULL;
}

typedef struct shm_detach_work {
    shm_t *shm;
    uint64_t uaddr;
    uint64_t size;
} shm_detach_work_t;

static shm_mapping_t *mapping_detach(task_t *task, shm_mapping_t *target) {
    for (shm_mapping_t **pp = &task->shm_ids; *pp; pp = &(*pp)->next) {
        if (*pp == target) {
            *pp = target->next;
            target->next = NULL;
            return target;
        }
    }

    return NULL;
}

static bool shm_detach_prepare_mm_locked(task_t *task, task_mm_info_t *mm,
                                         shm_mapping_t *mapping,
                                         shm_detach_work_t *work,
                                         bool require_vma) {
    if (!task || !mm || !mapping || !work)
        return false;

    vma_manager_t *mgr = &mm->task_vma_mgr;
    vma_t *vma = vma_find(mgr, mapping->uaddr);
    if ((!vma || vma->vm_type != VMA_TYPE_SHM ||
         vma->vm_start != mapping->uaddr) &&
        require_vma)
        return false;

    *work = (shm_detach_work_t){
        .shm = mapping->shm,
    };

    if (vma && vma->vm_type == VMA_TYPE_SHM &&
        vma->vm_start == mapping->uaddr) {
        work->uaddr = vma->vm_start;
        work->size = vma->vm_end - vma->vm_start;

        if (vma_remove(mgr, vma) != 0)
            return false;

        vma_free(vma);
    }

    mapping_detach(task, mapping);
    free(mapping);
    return true;
}

static bool shm_detach_prepare_locked(task_t *task, shm_mapping_t *mapping,
                                      shm_detach_work_t *work,
                                      bool require_vma) {
    return shm_detach_prepare_mm_locked(task, task ? task->mm : NULL, mapping,
                                        work, require_vma);
}

static void shm_detach_finish_mm(task_t *task, task_mm_info_t *mm,
                                 const shm_detach_work_t *work) {
    if (!task || !work)
        return;

    if (mm && work->size)
        unmap_page_range_mm_batched(mm, work->uaddr, work->size);

    spin_lock(&shm_op_lock);
    if (work->shm) {
        if (work->shm->nattch > 0)
            work->shm->nattch--;
        work->shm->dtime = shm_now_seconds();
        work->shm->lpid = task->pid;
        shm_try_free_locked(work->shm);
    }
    spin_unlock(&shm_op_lock);
}

static void shm_detach_finish(task_t *task, const shm_detach_work_t *work) {
    shm_detach_finish_mm(task, task ? task->mm : NULL, work);
}

void shm_try_reap_by_vnode(struct vfs_inode *node) { (void)node; }

size_t shm_snapshot(shm_snapshot_entry_t *entries, size_t max_entries) {
    size_t count = 0;

    spin_lock(&shm_op_lock);
    for (shm_t *shm = shm_list; shm; shm = shm->next) {
        if (entries && count < max_entries) {
            entries[count].key = shm->key;
            entries[count].shmid = shm->shmid;
            entries[count].mode = shm->mode;
            entries[count].size = shm->size;
            entries[count].cpid = shm->cpid;
            entries[count].lpid = shm->lpid;
            entries[count].nattch = shm->nattch;
        }
        count++;
    }
    spin_unlock(&shm_op_lock);

    return count;
}

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
    vma_t *vma;
    shm_mapping_t *mapping;
    void *new_backing = NULL;
    size_t size;
    bool need_backing;

    spin_lock(&shm_op_lock);

    shm = shm_find_id_locked(shmid);
    if (!shm) {
        err = -EINVAL;
        goto out_unlock_shm;
    }

    size = shm->size;
    need_backing = shm->addr == NULL;
    shm->nattch++;
    spin_unlock(&shm_op_lock);

    if (need_backing) {
        new_backing = alloc_frames_bytes(size);
        if (!new_backing) {
            err = -ENOMEM;
            goto out_put_attach;
        }
        memset(new_backing, 0, size);

        spin_lock(&shm_op_lock);
        if (!shm->addr) {
            shm->addr = new_backing;
            new_backing = NULL;
        }
        spin_unlock(&shm_op_lock);

        if (new_backing) {
            free_frames_bytes(new_backing, size);
            new_backing = NULL;
        }
    }

    vma = vma_alloc();
    if (!vma) {
        err = -ENOMEM;
        goto out_put_attach;
    }
    mapping = calloc(1, sizeof(*mapping));
    if (!mapping) {
        vma_free(vma);
        err = -ENOMEM;
        goto out_put_attach;
    }
    mapping->shm = shm;

    spin_lock(&mgr->lock);

    if (!shmaddr) {
        shmaddr = find_free_region(mgr, size);
        if (!shmaddr) {
            err = -ENOMEM;
            goto out_unlock_mgr_free;
        }
    }

    addr = (uint64_t)shmaddr;
    if (addr) {
        if (shmflg & SHM_RND) {
            addr = PADDING_DOWN(addr, PAGE_SIZE);
        } else if (addr & (PAGE_SIZE - 1)) {
            err = -EINVAL;
            goto out_unlock_mgr_free;
        }
    }

    if (vma_find_intersection(mgr, addr, addr + size)) {
        err = -EINVAL;
        goto out_unlock_mgr_free;
    }

    vma->vm_start = addr;
    vma->vm_end = addr + size;
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
        free(mapping);
        err = -ENOMEM;
        goto out_unlock_mgr;
    }

    spin_lock(&shm_op_lock);
    mapping->uaddr = addr;
    mapping->next = current_task->shm_ids;
    current_task->shm_ids = mapping;
    mapping = NULL;
    shm->atime = shm_now_seconds();
    shm->lpid = current_task->pid;
    spin_unlock(&shm_op_lock);
    spin_unlock(&mgr->lock);
    return (void *)addr;

out_unlock_mgr_free:
    vma_free(vma);
    free(mapping);
out_unlock_mgr:
    spin_unlock(&mgr->lock);
out_put_attach:
    spin_lock(&shm_op_lock);
    if (shm->nattch > 0)
        shm->nattch--;
    shm_try_free_locked(shm);
out_unlock_shm:
    spin_unlock(&shm_op_lock);
    return (void *)(int64_t)err;
}

uint64_t sys_shmdt(void *shmaddr) {
    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
    shm_mapping_t *m;
    shm_detach_work_t work = {0};

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

    if (!shm_detach_prepare_locked(current_task, m, &work, true)) {
        spin_unlock(&shm_op_lock);
        spin_unlock(&mgr->lock);
        return -EINVAL;
    }

    spin_unlock(&shm_op_lock);
    spin_unlock(&mgr->lock);

    shm_detach_finish(current_task, &work);
    return 0;
}

uint64_t sys_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
    shm_t *shm;

    if (cmd == IPC_INFO || cmd == SHM_INFO) {
        size_t count = 0;
        size_t pages = 0;
        struct shminfo info = {0};
        struct shm_info dinfo = {0};

        spin_lock(&shm_op_lock);
        for (shm_t *s = shm_list; s; s = s->next) {
            count++;
            pages += s->size / PAGE_SIZE;
        }
        spin_unlock(&shm_op_lock);

        if (!buf)
            return -EFAULT;

        if (cmd == IPC_INFO) {
            info.shmmax = 1ULL << 30;
            info.shmmin = 1;
            info.shmmni = 4096;
            info.shmseg = 4096;
            info.shmall = pages ? pages : (1ULL << 18);
            if (copy_to_user(buf, &info, sizeof(info)))
                return -EFAULT;
            return 0;
        }

        dinfo.used_ids = (int)count;
        dinfo.shm_tot = pages;
        dinfo.shm_rss = pages;
        if (copy_to_user(buf, &dinfo, sizeof(dinfo)))
            return -EFAULT;
        return 0;
    }

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
    case SHM_STAT: {
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
        return shm->shmid;
    }
    case IPC_SET:
        if (!buf) {
            spin_unlock(&shm_op_lock);
            return -EINVAL;
        }
        {
            struct shmid_ds user_info;
            if (copy_from_user(&user_info, buf, sizeof(user_info))) {
                spin_unlock(&shm_op_lock);
                return -EFAULT;
            }
            shm->uid = user_info.shm_perm.uid;
            shm->gid = user_info.shm_perm.gid;
            shm->mode = user_info.shm_perm.mode & 0777;
            shm->ctime = shm_now_seconds();
        }
        break;
    case SHM_LOCK:
        shm->mode |= 02000;
        break;
    case SHM_UNLOCK:
        shm->mode &= ~02000;
        break;
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
        shm_mapping_t *cm = calloc(1, sizeof(*cm));
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

void shm_exec(task_t *task, task_mm_info_t *mm) {
    if (!task || !mm)
        return;

    vma_manager_t *mgr = &mm->task_vma_mgr;

    while (true) {
        shm_detach_work_t work = {0};
        spin_lock(&mgr->lock);
        spin_lock(&shm_op_lock);

        shm_mapping_t *m = task->shm_ids;
        if (!m) {
            spin_unlock(&shm_op_lock);
            spin_unlock(&mgr->lock);
            break;
        }

        if (!shm_detach_prepare_mm_locked(task, mm, m, &work, false)) {
            spin_unlock(&shm_op_lock);
            spin_unlock(&mgr->lock);
            break;
        }

        spin_unlock(&shm_op_lock);
        spin_unlock(&mgr->lock);

        shm_detach_finish_mm(task, mm, &work);
    }
}

void shm_exit(task_t *task) {
    vma_manager_t *mgr;

    if (!task || !task->arch_context || !task->mm)
        return;

    mgr = &task->mm->task_vma_mgr;

    while (true) {
        shm_detach_work_t work = {0};
        spin_lock(&mgr->lock);
        spin_lock(&shm_op_lock);

        shm_mapping_t *m = task->shm_ids;
        if (!m) {
            spin_unlock(&shm_op_lock);
            spin_unlock(&mgr->lock);
            break;
        }

        if (!shm_detach_prepare_locked(task, m, &work, false)) {
            spin_unlock(&shm_op_lock);
            spin_unlock(&mgr->lock);
            break;
        }

        spin_unlock(&shm_op_lock);
        spin_unlock(&mgr->lock);

        shm_detach_finish(task, &work);
    }
}
