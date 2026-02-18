#include <fs/vfs/vfs.h>
#include <mm/mm.h>
#include <mm/shm.h>
#include <task/task.h>

static shm_t *shm_list = NULL;
static int next_shmid = 1;
static spinlock_t shm_op_lock = SPIN_INIT;
static int shmfs_fsid = 0;

#define PAGE_ALIGN_UP(x)                                                       \
    (((x) + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1))

static int shmfs_mount(uint64_t dev, vfs_node_t node);
static void shmfs_unmount(vfs_node_t node);
static int shmfs_remount(vfs_node_t old, vfs_node_t node);
static void shmfs_open(void *parent, const char *name, vfs_node_t node);
static ssize_t shmfs_read(fd_t *fd, void *addr, size_t offset, size_t size);
static ssize_t shmfs_write(fd_t *fd, const void *addr, size_t offset,
                           size_t size);
static bool shmfs_close(void *current);
static ssize_t shmfs_readlink(void *file, void *addr, size_t offset,
                              size_t size);
static int shmfs_mk(void *parent, const char *name, vfs_node_t node);
static int shmfs_mknod(void *parent, const char *name, vfs_node_t node,
                       uint16_t mode, int dev);
static int shmfs_chmod(vfs_node_t node, uint16_t mode);
static int shmfs_chown(vfs_node_t node, uint64_t uid, uint64_t gid);
static int shmfs_stat(void *file, vfs_node_t node);
static int shmfs_rename(void *current, const char *new);
static void *shmfs_map(fd_t *file, void *addr, size_t offset, size_t size,
                       size_t prot, size_t flags);
static int shmfs_ioctl(void *file, ssize_t cmd, ssize_t arg);
static int shmfs_poll(void *file, size_t events);
static void shmfs_resize(void *current, uint64_t size);
static int shmfs_delete(void *parent, vfs_node_t node);
static void shmfs_free_handle(void *handle);

static struct vfs_callback shmfs_callbacks = {
    .mount = shmfs_mount,
    .unmount = shmfs_unmount,
    .remount = shmfs_remount,
    .open = shmfs_open,
    .close = shmfs_close,
    .read = shmfs_read,
    .write = shmfs_write,
    .readlink = shmfs_readlink,
    .mkdir = shmfs_mk,
    .mkfile = shmfs_mk,
    .link = shmfs_mk,
    .symlink = shmfs_mk,
    .mknod = shmfs_mknod,
    .chmod = shmfs_chmod,
    .chown = shmfs_chown,
    .delete = shmfs_delete,
    .rename = shmfs_rename,
    .stat = shmfs_stat,
    .map = shmfs_map,
    .ioctl = shmfs_ioctl,
    .poll = shmfs_poll,
    .resize = shmfs_resize,

    .free_handle = shmfs_free_handle,
};

static fs_t shmfs = {
    .name = "shmfs",
    .magic = 0,
    .callback = &shmfs_callbacks,
    .flags = FS_FLAGS_HIDDEN | FS_FLAGS_VIRTUAL,
};

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

static int shm_register_fs_locked(void) {
    if (shmfs_fsid > 0)
        return 0;

    shmfs_fsid = vfs_regist(&shmfs);
    if (shmfs_fsid <= 0)
        return -ENOSYS;

    return 0;
}

static int shm_create_dev_node_locked(shm_t *shm) {
    int ret = shm_register_fs_locked();
    if (ret < 0)
        return ret;

    vfs_node_t shm_dir = vfs_open("/dev/shm", 0);
    if (!shm_dir) {
        vfs_mkdir("/dev/shm");
        shm_dir = vfs_open("/dev/shm", 0);
    }
    if (!shm_dir || !(shm_dir->type & file_dir))
        return -ENOENT;

    sprintf(shm->node_name, "sysv_%d", shm->shmid);

    if (vfs_child_find(shm_dir, shm->node_name))
        return -EEXIST;

    vfs_node_t node = vfs_child_append(shm_dir, shm->node_name, shm);
    if (!node)
        return -ENOMEM;

    node->type = file_none;
    node->fsid = shmfs_fsid;
    node->mode = 0600;
    node->owner = shm->uid;
    node->group = shm->gid;
    node->size = shm->size;
    node->handle = shm;

    shm->node = node;

    return 0;
}

static void shm_try_free_locked(shm_t *shm) {
    if (!shm)
        return;
    if (!shm->marked_destroy || shm->nattch > 0)
        return;
    if (shm->node && shm->node->refcount > 0)
        return;

    shm_unlink_locked(shm);

    if (shm->node) {
        shm->node->handle = NULL;
        vfs_delete(shm->node);
        shm->node = NULL;
    }

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
    for (shm_mapping_t *m = task->shm_ids; m; m = m->next) {
        if (m->uaddr == uaddr)
            return m;
    }
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

    vma_t *vma = vma_find(mgr, m->uaddr);
    if (vma && vma->vm_type == VMA_TYPE_SHM && vma->vm_start == m->uaddr) {
        unmap_page_range(get_current_page_dir(true), vma->vm_start,
                         vma->vm_end - vma->vm_start);
        vma_remove(mgr, vma);
        vma_free(vma);
    }

    if (shm) {
        if (shm->nattch > 0)
            shm->nattch--;
        shm_try_free_locked(shm);
    }
}

static int shmfs_mount(uint64_t dev, vfs_node_t node) { return 0; }

static void shmfs_unmount(vfs_node_t node) {}

static int shmfs_remount(vfs_node_t old, vfs_node_t node) { return 0; }

static void shmfs_open(void *parent, const char *name, vfs_node_t node) {}

static ssize_t shmfs_readlink(void *file, void *addr, size_t offset,
                              size_t size) {
    return -EPERM;
}

static int shmfs_mk(void *parent, const char *name, vfs_node_t node) {
    return -EPERM;
}

static int shmfs_mknod(void *parent, const char *name, vfs_node_t node,
                       uint16_t mode, int dev) {
    return -EPERM;
}

static int shmfs_chmod(vfs_node_t node, uint16_t mode) { return -EPERM; }

static int shmfs_chown(vfs_node_t node, uint64_t uid, uint64_t gid) {
    return -EPERM;
}

static ssize_t shmfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    shm_t *shm = (fd && fd->node) ? (shm_t *)fd->node->handle : NULL;
    if (!shm)
        return -EINVAL;

    spin_lock(&shm_op_lock);

    if (offset >= shm->size) {
        spin_unlock(&shm_op_lock);
        return 0;
    }

    size_t copy_size = MIN(size, shm->size - offset);
    int ret = shm_ensure_backing_locked(shm);
    if (ret < 0) {
        spin_unlock(&shm_op_lock);
        return ret;
    }

    memcpy(addr, (uint8_t *)shm->addr + offset, copy_size);
    spin_unlock(&shm_op_lock);

    return copy_size;
}

static ssize_t shmfs_write(fd_t *fd, const void *addr, size_t offset,
                           size_t size) {
    shm_t *shm = (fd && fd->node) ? (shm_t *)fd->node->handle : NULL;
    if (!shm)
        return -EINVAL;

    spin_lock(&shm_op_lock);

    if (offset >= shm->size) {
        spin_unlock(&shm_op_lock);
        return 0;
    }

    size_t copy_size = MIN(size, shm->size - offset);
    int ret = shm_ensure_backing_locked(shm);
    if (ret < 0) {
        spin_unlock(&shm_op_lock);
        return ret;
    }

    memcpy((uint8_t *)shm->addr + offset, addr, copy_size);
    spin_unlock(&shm_op_lock);

    return copy_size;
}

static int shmfs_stat(void *file, vfs_node_t node) {
    shm_t *shm = file;
    if (!shm || !node)
        return -EINVAL;

    spin_lock(&shm_op_lock);
    node->size = shm->size;
    node->owner = shm->uid;
    node->group = shm->gid;
    spin_unlock(&shm_op_lock);

    return 0;
}

static int shmfs_rename(void *current, const char *new) { return -EPERM; }

static void *shmfs_map(fd_t *file, void *addr, size_t offset, size_t size,
                       size_t prot, size_t flags) {
    (void)flags;

    shm_t *shm = (file && file->node) ? (shm_t *)file->node->handle : NULL;
    if (!shm)
        return (void *)(int64_t)-EINVAL;

    spin_lock(&shm_op_lock);

    if (offset >= shm->size || size > shm->size - offset) {
        spin_unlock(&shm_op_lock);
        return (void *)(int64_t)-EINVAL;
    }

    int ret = shm_ensure_backing_locked(shm);
    if (ret < 0) {
        spin_unlock(&shm_op_lock);
        return (void *)(int64_t)ret;
    }

    uint64_t pt_flags = PT_FLAG_U;
    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;
    if (!(pt_flags & (PT_FLAG_R | PT_FLAG_W | PT_FLAG_X)))
        pt_flags |= PT_FLAG_R;

    map_page_range(get_current_page_dir(true), (uint64_t)addr,
                   virt_to_phys((uint64_t)shm->addr + offset), size, pt_flags);

    spin_unlock(&shm_op_lock);
    return addr;
}

static int shmfs_ioctl(void *file, ssize_t cmd, ssize_t arg) { return -EPERM; }

static int shmfs_poll(void *file, size_t events) { return 0; }

static void shmfs_resize(void *current, uint64_t size) {}

static int shmfs_delete(void *parent, vfs_node_t node) {
    if (!node)
        return -EINVAL;
    if (node->handle) {
        shm_t *shm = (shm_t *)node->handle;
        if (!shm->marked_destroy)
            return -EPERM;
    }
    return 0;
}

static bool shmfs_close(void *current) {
    shm_t *shm = current;

    spin_lock(&shm_op_lock);
    shm_try_free_locked(shm);
    spin_unlock(&shm_op_lock);

    return false;
}

static void shmfs_free_handle(void *handle) {}

void shm_try_reap_by_vnode(struct vfs_node *node) {
    if (!node)
        return;

    spin_lock(&shm_op_lock);

    for (shm_t *s = shm_list; s; s = s->next) {
        if (s->node == node) {
            shm_try_free_locked(s);
            break;
        }
    }

    spin_unlock(&shm_op_lock);
}

uint64_t sys_shmget(int key, int size, int shmflg) {
    if (size <= 0)
        return -EINVAL;

    spin_lock(&shm_op_lock);

    if (key != IPC_PRIVATE) {
        shm_t *s = shm_find_key_locked(key);
        if (s) {
            if (shmflg & IPC_EXCL) {
                spin_unlock(&shm_op_lock);
                return -EEXIST;
            }
            spin_unlock(&shm_op_lock);
            return s->shmid;
        }
    }

    if (key != IPC_PRIVATE && !(shmflg & IPC_CREAT)) {
        spin_unlock(&shm_op_lock);
        return -ENOENT;
    }

    shm_t *shm = malloc(sizeof(shm_t));
    if (!shm) {
        spin_unlock(&shm_op_lock);
        return -ENOMEM;
    }

    memset(shm, 0, sizeof(shm_t));
    shm->shmid = next_shmid++;
    shm->key = key;
    shm->size = PAGE_ALIGN_UP((size_t)size);
    shm->uid = current_task->uid;
    shm->gid = current_task->gid;
    shm->nattch = 0;
    shm->marked_destroy = false;

    int ret = shm_create_dev_node_locked(shm);
    if (ret < 0) {
        free(shm);
        spin_unlock(&shm_op_lock);
        return ret;
    }

    shm->next = shm_list;
    shm_list = shm;

    uint64_t shmid = shm->shmid;
    spin_unlock(&shm_op_lock);

    return shmid;
}

void *sys_shmat(int shmid, void *shmaddr, int shmflg) {
    spin_lock(&shm_op_lock);

    shm_t *shm = shm_find_id_locked(shmid);
    if (!shm || shm->marked_destroy) {
        spin_unlock(&shm_op_lock);
        return (void *)(int64_t)-EINVAL;
    }

    int ret = shm_ensure_backing_locked(shm);
    if (ret < 0) {
        spin_unlock(&shm_op_lock);
        return (void *)(int64_t)ret;
    }

    vma_manager_t *mgr = &current_task->arch_context->mm->task_vma_mgr;

    if (!shmaddr) {
        shmaddr = find_free_region(mgr, shm->size);
        if (!shmaddr) {
            spin_unlock(&shm_op_lock);
            return (void *)(int64_t)-ENOMEM;
        }
    }

    uint64_t addr = (uint64_t)shmaddr;
    if (vma_find_intersection(mgr, addr, addr + shm->size)) {
        spin_unlock(&shm_op_lock);
        return (void *)(int64_t)-EINVAL;
    }

    uint64_t flags = PT_FLAG_U | PT_FLAG_R;
    if (!(shmflg & SHM_RDONLY))
        flags |= PT_FLAG_W;

    map_page_range(get_current_page_dir(true), addr,
                   virt_to_phys((uint64_t)shm->addr), shm->size, flags);

    vma_t *vma = vma_alloc();
    if (!vma) {
        unmap_page_range(get_current_page_dir(true), addr, shm->size);
        spin_unlock(&shm_op_lock);
        return (void *)(int64_t)-ENOMEM;
    }

    vma->vm_start = addr;
    vma->vm_end = addr + shm->size;
    vma->vm_type = VMA_TYPE_SHM;
    vma->vm_flags = VMA_ANON | VMA_SHM;
    vma->shm = shm;
    vma->shm_id = shm->shmid;
    vma->node = NULL;

    if (vma_insert(mgr, vma) != 0) {
        vma_free(vma);
        unmap_page_range(get_current_page_dir(true), addr, shm->size);
        spin_unlock(&shm_op_lock);
        return (void *)(int64_t)-ENOMEM;
    }

    if (!mapping_add(current_task, shm, addr)) {
        vma_remove(mgr, vma);
        vma_free(vma);
        unmap_page_range(get_current_page_dir(true), addr, shm->size);
        spin_unlock(&shm_op_lock);
        return (void *)(int64_t)-ENOMEM;
    }

    shm->nattch++;
    spin_unlock(&shm_op_lock);

    return shmaddr;
}

uint64_t sys_shmdt(void *shmaddr) {
    if (!shmaddr)
        return -EINVAL;

    spin_lock(&shm_op_lock);

    shm_mapping_t *m = mapping_find(current_task, (uint64_t)shmaddr);
    if (!m) {
        spin_unlock(&shm_op_lock);
        return -EINVAL;
    }

    do_shmdt_one(current_task, m);
    mapping_remove(current_task, m);

    spin_unlock(&shm_op_lock);
    return 0;
}

uint64_t sys_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
    spin_lock(&shm_op_lock);

    shm_t *shm = shm_find_id_locked(shmid);
    if (!shm) {
        spin_unlock(&shm_op_lock);
        return -EINVAL;
    }

    switch (cmd) {
    case IPC_RMID:
        shm->marked_destroy = true;
        if (shm->node && shm->node->refcount > 0)
            vfs_delete(shm->node);
        shm_try_free_locked(shm);
        break;

    case IPC_STAT:
        if (!buf) {
            spin_unlock(&shm_op_lock);
            return -EINVAL;
        }
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
        shm_mapping_t *cm = malloc(sizeof(shm_mapping_t));
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
    spin_lock(&shm_op_lock);

    shm_mapping_t *m = task->shm_ids;
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
    spin_lock(&shm_op_lock);

    shm_mapping_t *m = task->shm_ids;
    while (m) {
        shm_mapping_t *next = m->next;

        do_shmdt_one(task, m);
        free(m);

        m = next;
    }
    task->shm_ids = NULL;

    spin_unlock(&shm_op_lock);
}
