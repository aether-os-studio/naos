#include <fs/vfs/vfs.h>
#include <fs/proc.h>
#include <mm/mm_syscall.h>
#include <mm/page.h>
#include <mm/vma.h>
#include <task/task.h>
#include <init/callbacks.h>

#define MEMFDFS_MAGIC 0x6d656d66ULL

static struct vfs_file_system_type memfdfs_fs_type;
static const struct vfs_super_operations memfdfs_super_ops;
static const struct vfs_inode_operations memfdfs_inode_ops;
static const struct vfs_file_operations memfdfs_dir_file_ops;
static const struct vfs_file_operations memfdfs_file_ops;
static mutex_t memfdfs_mount_lock;
static struct vfs_mount *memfdfs_internal_mnt;

struct memfd_ctx {
    vfs_node_t *node;
    char name[64];
    uint64_t *pages;
    size_t page_slots;
    uint64_t len;
    int flags;
    spinlock_t lock;
};

typedef struct memfdfs_info {
    spinlock_t lock;
    ino64_t next_ino;
} memfdfs_info_t;

typedef struct memfdfs_inode_info {
    struct vfs_inode vfs_inode;
} memfdfs_inode_info_t;

static inline memfdfs_info_t *memfdfs_sb_info(struct vfs_super_block *sb) {
    return sb ? (memfdfs_info_t *)sb->s_fs_info : NULL;
}

static inline struct memfd_ctx *memfd_file_handle(struct vfs_file *file) {
    if (!file)
        return NULL;
    if (file->private_data)
        return (struct memfd_ctx *)file->private_data;
    if (!file->f_inode)
        return NULL;
    return (struct memfd_ctx *)file->f_inode->i_private;
}

static struct vfs_inode *memfdfs_alloc_inode(struct vfs_super_block *sb) {
    memfdfs_inode_info_t *info = calloc(1, sizeof(*info));
    (void)sb;
    return info ? &info->vfs_inode : NULL;
}

static void memfdfs_destroy_ctx(struct memfd_ctx *ctx) {
    if (!ctx)
        return;
    for (size_t i = 0; i < ctx->page_slots; i++) {
        if (ctx->pages[i])
            address_release(ctx->pages[i]);
    }
    free(ctx->pages);
    free(ctx);
}

static void memfdfs_destroy_inode(struct vfs_inode *inode) {
    if (!inode)
        return;
    if (inode->i_private) {
        memfdfs_destroy_ctx((struct memfd_ctx *)inode->i_private);
        inode->i_private = NULL;
    }
    free(container_of(inode, memfdfs_inode_info_t, vfs_inode));
}

static int memfdfs_init_fs_context(struct vfs_fs_context *fc) {
    (void)fc;
    return 0;
}

static int memfdfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb;
    memfdfs_info_t *fsi;
    struct vfs_inode *inode;
    struct vfs_dentry *root;

    sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    if (!sb)
        return -ENOMEM;

    fsi = calloc(1, sizeof(*fsi));
    if (!fsi) {
        vfs_put_super(sb);
        return -ENOMEM;
    }

    spin_init(&fsi->lock);
    fsi->next_ino = 1;
    sb->s_magic = MEMFDFS_MAGIC;
    sb->s_fs_info = fsi;
    sb->s_op = &memfdfs_super_ops;
    sb->s_type = &memfdfs_fs_type;

    inode = vfs_alloc_inode(sb);
    if (!inode) {
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    inode->i_ino = 1;
    inode->inode = 1;
    inode->i_mode = S_IFDIR | 0700;
    inode->type = file_dir;
    inode->i_nlink = 2;
    inode->i_op = &memfdfs_inode_ops;
    inode->i_fop = &memfdfs_dir_file_ops;

    root = vfs_d_alloc(sb, NULL, NULL);
    if (!root) {
        vfs_iput(inode);
        free(fsi);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    vfs_d_instantiate(root, inode);
    sb->s_root = root;
    fc->sb = sb;
    return 0;
}

static void memfdfs_put_super(struct vfs_super_block *sb) {
    if (sb && sb->s_fs_info)
        free(sb->s_fs_info);
}

static int memfdfs_getattr(const struct vfs_path *path, struct vfs_kstat *stat,
                           uint32_t request_mask, unsigned int flags) {
    (void)request_mask;
    (void)flags;
    vfs_fill_generic_kstat(path, stat);
    return 0;
}

static const struct vfs_super_operations memfdfs_super_ops = {
    .alloc_inode = memfdfs_alloc_inode,
    .destroy_inode = memfdfs_destroy_inode,
    .put_super = memfdfs_put_super,
};

static struct vfs_file_system_type memfdfs_fs_type = {
    .name = "memfdfs",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = memfdfs_init_fs_context,
    .get_tree = memfdfs_get_tree,
};

static struct vfs_mount *memfdfs_get_internal_mount(void) {
    int ret;

    mutex_lock(&memfdfs_mount_lock);
    if (!memfdfs_internal_mnt) {
        ret = vfs_kern_mount("memfdfs", 0, NULL, NULL, &memfdfs_internal_mnt);
        if (ret < 0)
            memfdfs_internal_mnt = NULL;
    }
    if (memfdfs_internal_mnt)
        vfs_mntget(memfdfs_internal_mnt);
    mutex_unlock(&memfdfs_mount_lock);
    return memfdfs_internal_mnt;
}

static ino64_t memfdfs_next_ino(struct vfs_super_block *sb) {
    memfdfs_info_t *fsi = memfdfs_sb_info(sb);
    ino64_t ino;

    spin_lock(&fsi->lock);
    ino = ++fsi->next_ino;
    spin_unlock(&fsi->lock);
    return ino;
}

static size_t memfd_pages_for_size(uint64_t size) {
    return size ? (size_t)(PADDING_UP(size, PAGE_SIZE) / PAGE_SIZE) : 0;
}

static int memfd_ensure_page_slots_locked(struct memfd_ctx *ctx, size_t slots) {
    if (!ctx || slots <= ctx->page_slots)
        return 0;

    size_t new_slots = ctx->page_slots ? ctx->page_slots : 1;
    while (new_slots < slots) {
        if (new_slots > SIZE_MAX / 2) {
            new_slots = slots;
            break;
        }
        new_slots *= 2;
    }
    if (new_slots < slots)
        new_slots = slots;

    uint64_t *new_pages = calloc(new_slots, sizeof(uint64_t));
    if (!new_pages)
        return -ENOMEM;

    if (ctx->pages && ctx->page_slots > 0) {
        memcpy(new_pages, ctx->pages, ctx->page_slots * sizeof(uint64_t));
        free(ctx->pages);
    }

    ctx->pages = new_pages;
    ctx->page_slots = new_slots;
    return 0;
}

static int memfd_resolve_page_locked(struct memfd_ctx *ctx, size_t page_idx,
                                     bool create, uint64_t *out_paddr) {
    if (!ctx || !out_paddr)
        return -EINVAL;

    *out_paddr = 0;
    if (page_idx >= ctx->page_slots) {
        if (!create)
            return 0;
        int ret = memfd_ensure_page_slots_locked(ctx, page_idx + 1);
        if (ret < 0)
            return ret;
    }

    uint64_t paddr = ctx->pages[page_idx];
    if (!paddr && create) {
        paddr = alloc_frames(1);
        if (!paddr)
            return -ENOMEM;
        memset((void *)phys_to_virt(paddr), 0, PAGE_SIZE);
        ctx->pages[page_idx] = paddr;
    }

    *out_paddr = paddr;
    return 0;
}

static void memfd_zap_mappings(vfs_node_t *node, uint64_t file_start,
                               uint64_t file_end) {
    if (!node || file_start >= file_end)
        return;

    spin_lock(&task_queue_lock);
    if (!task_pid_map.buckets) {
        spin_unlock(&task_queue_lock);
        return;
    }

    for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
        hashmap_entry_t *entry = &task_pid_map.buckets[i];
        if (!hashmap_entry_is_occupied(entry))
            continue;

        task_t *task = (task_t *)entry->value;
        if (!task || !task->mm)
            continue;

        task_mm_info_t *mm = task->mm;
        vma_manager_t *mgr = &mm->task_vma_mgr;

        spin_lock(&mgr->lock);
        uint64_t cursor = USER_MMAP_START;
        while (cursor < USER_MMAP_END) {
            vma_t *vma = vma_find_intersection(mgr, cursor, USER_MMAP_END);
            if (!vma)
                break;

            uint64_t next = vma->vm_end;
            if (vma->vm_type == VMA_TYPE_FILE && vma->node == node &&
                (vma->vm_flags & VMA_SHARED) && vma->vm_offset >= 0) {
                uint64_t vma_file_start = (uint64_t)vma->vm_offset;
                uint64_t vma_len = vma->vm_end - vma->vm_start;
                uint64_t vma_file_end = UINT64_MAX;
                if (vma_len <= UINT64_MAX - vma_file_start)
                    vma_file_end = vma_file_start + vma_len;

                uint64_t overlap_start = MAX(file_start, vma_file_start);
                uint64_t overlap_end = MIN(file_end, vma_file_end);
                if (overlap_start < overlap_end) {
                    uint64_t unmap_start =
                        vma->vm_start + (overlap_start - vma_file_start);
                    uint64_t unmap_len = overlap_end - overlap_start;

                    spin_lock(&mm->lock);
                    unmap_page_range_mm(mm, unmap_start, unmap_len);
                    spin_unlock(&mm->lock);
                }
            }

            if (next <= cursor)
                break;
            cursor = next;
        }

        spin_unlock(&mgr->lock);
    }

    spin_unlock(&task_queue_lock);
}

static ssize_t memfdfs_read(struct vfs_file *file, void *buf, size_t count,
                            loff_t *ppos) {
    struct memfd_ctx *ctx = memfd_file_handle(file);
    size_t copy_len;
    size_t copied = 0;

    if (!ctx || !ppos)
        return -EINVAL;
    if ((uint64_t)*ppos >= ctx->len)
        return 0;

    copy_len = (size_t)MIN((uint64_t)count, ctx->len - (uint64_t)*ppos);

    spin_lock(&ctx->lock);
    while (copied < copy_len) {
        uint64_t file_off = (uint64_t)*ppos + copied;
        size_t page_idx = (size_t)(file_off / PAGE_SIZE);
        size_t in_page = (size_t)(file_off % PAGE_SIZE);
        size_t chunk = MIN(copy_len - copied, PAGE_SIZE - in_page);
        uint64_t paddr = 0;

        memfd_resolve_page_locked(ctx, page_idx, false, &paddr);
        if (paddr)
            memcpy((uint8_t *)buf + copied,
                   (uint8_t *)phys_to_virt(paddr) + in_page, chunk);
        else
            memset((uint8_t *)buf + copied, 0, chunk);
        copied += chunk;
    }
    spin_unlock(&ctx->lock);

    *ppos += (loff_t)copy_len;
    return (ssize_t)copy_len;
}

static ssize_t memfdfs_write(struct vfs_file *file, const void *buf,
                             size_t count, loff_t *ppos) {
    struct memfd_ctx *ctx = memfd_file_handle(file);
    uint64_t end;
    size_t copied = 0;

    if (!ctx || !ppos)
        return -EINVAL;
    if ((uint64_t)*ppos > UINT64_MAX - count)
        return -EFBIG;

    end = (uint64_t)*ppos + count;

    spin_lock(&ctx->lock);
    while (copied < count) {
        uint64_t file_off = (uint64_t)*ppos + copied;
        size_t page_idx = (size_t)(file_off / PAGE_SIZE);
        size_t in_page = (size_t)(file_off % PAGE_SIZE);
        size_t chunk = MIN(count - copied, PAGE_SIZE - in_page);
        uint64_t paddr = 0;
        int ret = memfd_resolve_page_locked(ctx, page_idx, true, &paddr);
        if (ret < 0) {
            spin_unlock(&ctx->lock);
            return ret;
        }

        memcpy((uint8_t *)phys_to_virt(paddr) + in_page,
               (const uint8_t *)buf + copied, chunk);
        copied += chunk;
    }

    if (end > ctx->len)
        ctx->len = end;
    if (ctx->node)
        ctx->node->i_size = ctx->len;
    spin_unlock(&ctx->lock);

    *ppos += (loff_t)count;
    return (ssize_t)count;
}

static int memfdfs_resize(struct vfs_inode *node, uint64_t size) {
    struct memfd_ctx *ctx = node ? (struct memfd_ctx *)node->i_private : NULL;
    size_t old_pages, new_pages;
    uint64_t old_len;

    if (!ctx)
        return -EINVAL;

    spin_lock(&ctx->lock);
    old_len = ctx->len;
    if (size == old_len) {
        spin_unlock(&ctx->lock);
        return 0;
    }

    old_pages = memfd_pages_for_size(old_len);
    new_pages = memfd_pages_for_size(size);

    if (size > old_len) {
        int ret = memfd_ensure_page_slots_locked(ctx, new_pages);
        if (ret < 0) {
            spin_unlock(&ctx->lock);
            return ret;
        }
        ctx->len = size;
        if (ctx->node)
            ctx->node->i_size = size;
        spin_unlock(&ctx->lock);
        return 0;
    }

    if ((size & (PAGE_SIZE - 1)) != 0) {
        size_t tail_page = (size_t)(size / PAGE_SIZE);
        uint64_t paddr = 0;
        if (memfd_resolve_page_locked(ctx, tail_page, false, &paddr) == 0 &&
            paddr) {
            memset((uint8_t *)phys_to_virt(paddr) + (size % PAGE_SIZE), 0,
                   PAGE_SIZE - (size % PAGE_SIZE));
        }
    }

    ctx->len = size;
    if (ctx->node)
        ctx->node->i_size = size;
    spin_unlock(&ctx->lock);

    uint64_t zap_start = PADDING_UP(size, PAGE_SIZE);
    uint64_t zap_end = PADDING_UP(old_len, PAGE_SIZE);
    if (zap_start < zap_end)
        memfd_zap_mappings(node, zap_start, zap_end);

    for (size_t i = new_pages; i < old_pages; i++) {
        uint64_t paddr = 0;

        spin_lock(&ctx->lock);
        if (i < ctx->page_slots) {
            paddr = ctx->pages[i];
            ctx->pages[i] = 0;
        }
        spin_unlock(&ctx->lock);

        if (paddr)
            address_release(paddr);
    }

    return 0;
}

static int memfdfs_setattr(struct vfs_dentry *dentry,
                           const struct vfs_kstat *stat) {
    struct vfs_inode *inode;
    int ret = 0;

    if (!dentry || !dentry->d_inode || !stat)
        return -EINVAL;

    inode = dentry->d_inode;
    if (stat->mode)
        inode->i_mode = stat->mode;
    inode->i_uid = stat->uid;
    inode->i_gid = stat->gid;

    if (!S_ISDIR(inode->i_mode) && stat->size != inode->i_size)
        ret = memfdfs_resize(inode, stat->size);

    inode->inode = inode->i_ino;
    inode->type = S_ISDIR(inode->i_mode)    ? file_dir
                  : S_ISLNK(inode->i_mode)  ? file_symlink
                  : S_ISBLK(inode->i_mode)  ? file_block
                  : S_ISCHR(inode->i_mode)  ? file_stream
                  : S_ISFIFO(inode->i_mode) ? file_fifo
                  : S_ISSOCK(inode->i_mode) ? file_socket
                                            : file_none;
    return ret;
}

static int memfdfs_fsync(struct vfs_file *file, loff_t start, loff_t end,
                         int datasync) {
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    return 0;
}

static int memfdfs_open(struct vfs_inode *inode, struct vfs_file *file) {
    if (!inode || !file)
        return -EINVAL;
    file->f_op = inode->i_fop;
    file->private_data = inode->i_private;
    return 0;
}

static int memfdfs_release(struct vfs_inode *inode, struct vfs_file *file) {
    (void)inode;
    if (file)
        file->private_data = NULL;
    return 0;
}

static void *memfdfs_mmap(struct vfs_file *file, void *addr, size_t offset,
                          size_t size, size_t prot, uint64_t flags) {
    if ((flags & MAP_TYPE) == MAP_PRIVATE)
        return general_map(file, (uint64_t)addr, size, prot, flags, offset);

    struct memfd_ctx *ctx = memfd_file_handle(file);
    if (!ctx)
        return (void *)(int64_t)-EINVAL;
    if (offset > SIZE_MAX - size)
        return (void *)(int64_t)-EINVAL;

    uint64_t pt_flags = PT_FLAG_U;
    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;
    if (!(pt_flags & (PT_FLAG_R | PT_FLAG_W | PT_FLAG_X)))
        pt_flags |= PT_FLAG_R;

    uint64_t start = (uint64_t)addr;
    uint64_t *pgdir = get_current_page_dir(true);

    spin_lock(&ctx->lock);
    for (uint64_t ptr = start; ptr < start + size; ptr += PAGE_SIZE) {
        uint64_t file_off = offset + (ptr - start);
        if (file_off >= ctx->len)
            break;

        uint64_t paddr = 0;
        int ret = memfd_resolve_page_locked(ctx, (size_t)(file_off / PAGE_SIZE),
                                            true, &paddr);
        if (ret < 0) {
            spin_unlock(&ctx->lock);
            return (void *)(int64_t)ret;
        }

        if (map_page_range(pgdir, ptr, paddr, PAGE_SIZE, pt_flags) != 0) {
            spin_unlock(&ctx->lock);
            return (void *)(int64_t)-ENOMEM;
        }
    }
    spin_unlock(&ctx->lock);

    return addr;
}

static loff_t memfdfs_llseek(struct vfs_file *file, loff_t offset, int whence) {
    loff_t pos;

    if (!file || !file->f_inode)
        return -EBADF;

    mutex_lock(&file->f_pos_lock);
    switch (whence) {
    case SEEK_SET:
        pos = offset;
        break;
    case SEEK_CUR:
        pos = file->f_pos + offset;
        break;
    case SEEK_END:
        pos = (loff_t)file->f_inode->i_size + offset;
        break;
    default:
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }
    if (pos < 0) {
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }
    file->f_pos = pos;
    mutex_unlock(&file->f_pos_lock);
    return pos;
}

static const struct vfs_inode_operations memfdfs_inode_ops = {
    .getattr = memfdfs_getattr,
    .setattr = memfdfs_setattr,
};

static const struct vfs_file_operations memfdfs_dir_file_ops = {
    .llseek = memfdfs_llseek,
    .open = memfdfs_open,
    .release = memfdfs_release,
};

static const struct vfs_file_operations memfdfs_file_ops = {
    .llseek = memfdfs_llseek,
    .read = memfdfs_read,
    .write = memfdfs_write,
    .mmap = memfdfs_mmap,
    .open = memfdfs_open,
    .release = memfdfs_release,
    .fsync = memfdfs_fsync,
};

#define MFD_CLOEXEC 0x0001U
#define MFD_ALLOW_SEALING 0x0002U
#define MFD_HUGETLB 0x0004U
#define MFD_NOEXEC_SEAL 0x0008U
#define MFD_EXEC 0x0010U

static int memfd_create_file(struct vfs_file **out_file, const char *name,
                             unsigned int flags, struct memfd_ctx **out_ctx) {
    struct vfs_mount *mnt;
    struct vfs_super_block *sb;
    struct vfs_inode *inode;
    struct vfs_dentry *dentry;
    struct vfs_qstr qname = {0};
    struct vfs_file *file;
    struct memfd_ctx *ctx;
    char label[80];

    if (!out_file)
        return -EINVAL;

    mnt = memfdfs_get_internal_mount();
    if (!mnt)
        return -ENODEV;
    sb = mnt->mnt_sb;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    if (name)
        strncpy(ctx->name, name, sizeof(ctx->name) - 1);
    ctx->flags = (int)flags;
    spin_init(&ctx->lock);

    inode = vfs_alloc_inode(sb);
    if (!inode) {
        free(ctx);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    inode->i_ino = memfdfs_next_ino(sb);
    inode->inode = inode->i_ino;
    inode->i_mode = S_IFREG | 0600;
    inode->type = file_none;
    inode->i_nlink = 1;
    inode->i_op = &memfdfs_inode_ops;
    inode->i_fop = &memfdfs_file_ops;
    inode->i_private = ctx;
    ctx->node = inode;

    snprintf(label, sizeof(label), "memfd-%s-%llu",
             ctx->name[0] ? ctx->name : "anon",
             (unsigned long long)inode->i_ino);
    vfs_qstr_make(&qname, label);
    dentry = vfs_d_alloc(sb, sb->s_root, &qname);
    if (!dentry) {
        inode->i_private = NULL;
        vfs_iput(inode);
        free(ctx);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    vfs_d_instantiate(dentry, inode);
    file = vfs_alloc_file(&(struct vfs_path){.mnt = mnt, .dentry = dentry},
                          O_RDWR);
    if (!file) {
        vfs_dput(dentry);
        inode->i_private = NULL;
        vfs_iput(inode);
        free(ctx);
        vfs_mntput(mnt);
        return -ENOMEM;
    }

    file->private_data = ctx;
    *out_file = file;
    if (out_ctx)
        *out_ctx = ctx;

    vfs_dput(dentry);
    vfs_iput(inode);
    vfs_mntput(mnt);
    return 0;
}

uint64_t sys_memfd_create(const char *name, unsigned int flags) {
    struct vfs_file *file = NULL;
    int ret;
    char kname[64] = {0};

    if ((flags & MFD_HUGETLB) || (flags & MFD_NOEXEC_SEAL) ||
        (flags & MFD_EXEC))
        return -EINVAL;
    if (name && copy_from_user_str(kname, name, sizeof(kname)))
        return -EFAULT;

    ret = memfd_create_file(&file, kname, flags, NULL);
    if (ret < 0)
        return (uint64_t)ret;

    ret = task_install_file(current_task, file,
                            (flags & MFD_CLOEXEC) ? FD_CLOEXEC : 0, 0);
    vfs_file_put(file);
    return (uint64_t)ret;
}

void memfd_init() {
    mutex_init(&memfdfs_mount_lock);
    vfs_register_filesystem(&memfdfs_fs_type);
}
