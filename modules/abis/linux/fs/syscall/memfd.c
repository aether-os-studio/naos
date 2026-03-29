#include <fs/vfs/vfs.h>
#include <fs/proc.h>
#include <mm/mm_syscall.h>
#include <mm/page.h>
#include <mm/vma.h>
#include <task/task.h>
#include <init/callbacks.h>

static int memfd_fsid = 0;

struct memfd_ctx {
    vfs_node_t *node;
    char name[64];
    uint64_t *pages;
    size_t page_slots;
    uint64_t len;
    int flags;
    spinlock_t lock;
};

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

static ssize_t memfd_read(fd_t *fd, void *buf, uint64_t offset, uint64_t len) {
    struct memfd_ctx *ctx = fd && fd->node ? fd->node->handle : NULL;
    if (!ctx)
        return -EINVAL;
    if (offset >= ctx->len)
        return 0;

    size_t copy_len = (size_t)MIN((uint64_t)len, ctx->len - offset);
    size_t copied = 0;

    spin_lock(&ctx->lock);
    while (copied < copy_len) {
        uint64_t file_off = offset + copied;
        size_t page_idx = (size_t)(file_off / PAGE_SIZE);
        size_t in_page = (size_t)(file_off % PAGE_SIZE);
        size_t chunk = MIN(copy_len - copied, PAGE_SIZE - in_page);
        uint64_t paddr = 0;

        memfd_resolve_page_locked(ctx, page_idx, false, &paddr);
        if (paddr) {
            memcpy((uint8_t *)buf + copied,
                   (uint8_t *)phys_to_virt(paddr) + in_page, chunk);
        } else {
            memset((uint8_t *)buf + copied, 0, chunk);
        }

        copied += chunk;
    }
    spin_unlock(&ctx->lock);

    return (ssize_t)copy_len;
}

static ssize_t memfd_write(fd_t *fd, const void *buf, uint64_t offset,
                           uint64_t len) {
    struct memfd_ctx *ctx = fd && fd->node ? fd->node->handle : NULL;
    if (!ctx)
        return -EINVAL;
    if (len == 0)
        return 0;
    if (offset > UINT64_MAX - len)
        return -EFBIG;

    uint64_t end = offset + len;
    size_t copied = 0;

    spin_lock(&ctx->lock);
    while (copied < len) {
        uint64_t file_off = offset + copied;
        size_t page_idx = (size_t)(file_off / PAGE_SIZE);
        size_t in_page = (size_t)(file_off % PAGE_SIZE);
        size_t chunk = MIN((size_t)(len - copied), PAGE_SIZE - in_page);
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
    ctx->node->size = ctx->len;
    spin_unlock(&ctx->lock);

    return (ssize_t)len;
}

bool memfd_close(vfs_node_t *node) {
    struct memfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return true;

    spin_lock(&ctx->lock);
    uint64_t *pages = ctx->pages;
    size_t page_slots = ctx->page_slots;
    ctx->pages = NULL;
    ctx->page_slots = 0;
    spin_unlock(&ctx->lock);

    for (size_t i = 0; i < page_slots; i++) {
        if (pages[i])
            address_release(pages[i]);
    }

    free(pages);
    ctx->node->handle = NULL;
    free(ctx);
    return true;
}

int memfd_stat(vfs_node_t *node) {
    struct memfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return -EINVAL;

    node->size = ctx->len;
    return 0;
}

int memfd_resize(vfs_node_t *node, uint64_t size) {
    struct memfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return -EINVAL;

    spin_lock(&ctx->lock);

    uint64_t old_len = ctx->len;
    if (size == old_len) {
        spin_unlock(&ctx->lock);
        return 0;
    }

    size_t old_pages = memfd_pages_for_size(old_len);
    size_t new_pages = memfd_pages_for_size(size);

    if (size > old_len) {
        int ret = memfd_ensure_page_slots_locked(ctx, new_pages);
        if (ret < 0) {
            spin_unlock(&ctx->lock);
            return ret;
        }

        ctx->len = size;
        ctx->node->size = size;
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
    ctx->node->size = size;
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

void *memfd_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
                size_t flags) {
    if ((flags & MAP_TYPE) == MAP_PRIVATE)
        return general_map(file, (uint64_t)addr, size, prot, flags, offset);

    struct memfd_ctx *ctx = file && file->node ? file->node->handle : NULL;
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

static vfs_operations_t callbacks = {
    .close = memfd_close,
    .read = memfd_read,
    .write = memfd_write,
    .map = memfd_map,
    .stat = memfd_stat,
    .resize = memfd_resize,
    .free_handle = vfs_generic_free_handle,
};

#define MFD_CLOEXEC 0x0001U
#define MFD_ALLOW_SEALING 0x0002U
#define MFD_HUGETLB 0x0004U
#define MFD_NOEXEC_SEAL 0x0008U
#define MFD_EXEC 0x0010U

uint64_t sys_memfd_create(const char *name, unsigned int flags) {
    if ((flags & MFD_HUGETLB))
        return -EINVAL;
    if ((flags & MFD_NOEXEC_SEAL) || (flags & MFD_EXEC))
        return -EINVAL;

    struct memfd_ctx *ctx = calloc(1, sizeof(struct memfd_ctx));
    if (!ctx)
        return -ENOMEM;

    strncpy(ctx->name, name, 63);
    ctx->name[63] = '\0';
    ctx->flags = flags;
    ctx->lock.lock = 0;

    vfs_node_t *node = vfs_node_alloc(NULL, NULL);
    node->type = file_none;
    node->fsid = memfd_fsid;
    node->handle = ctx;
    node->refcount++;
    node->size = 0;

    int fd = -1;
    int ret = -EMFILE;
    with_fd_info_lock(current_task->fd_info, {
        for (int i = 0; i < MAX_FD_NUM; i++) {
            if (!current_task->fd_info->fds[i]) {
                fd = i;
                break;
            }
        }

        if (fd < 0)
            break;

        fd_t *new_fd = fd_create(node, O_RDWR, !!(flags & MFD_CLOEXEC));
        if (!new_fd) {
            ret = -ENOMEM;
            fd = -1;
            break;
        }

        current_task->fd_info->fds[fd] = new_fd;
        on_open_file_call(current_task, fd);
        ret = 0;
    });

    if (ret < 0) {
        vfs_free(node);
        return ret;
    }

    ctx->node = node;
    return fd;
}

fs_t memfdfs = {
    .name = "memfdfs",
    .magic = 0,
    .ops = &callbacks,
    .flags = FS_FLAGS_HIDDEN | FS_FLAGS_VIRTUAL,
};

void memfd_init() { memfd_fsid = vfs_regist(&memfdfs); }
