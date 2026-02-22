#include <fs/vfs/vfs.h>
#include <fs/vfs/proc.h>
#include <mm/mm_syscall.h>
#include <mm/page.h>
#include <task/task.h>

static int memfd_fsid = 0;

struct memfd_ctx {
    vfs_node_t node;
    char name[64];
    uint8_t *data;
    size_t len;
    int flags;
    int refcount;
    spinlock_t lock;
};

static ssize_t memfd_read(fd_t *fd, void *buf, uint64_t offset, uint64_t len) {
    void *data = fd->node->handle;

    struct memfd_ctx *ctx = data;
    size_t avail = ctx->len - offset;
    if (avail <= 0)
        return 0;
    size_t copy_len = len < avail ? len : avail;
    memcpy(buf, ctx->data + offset, copy_len);
    return copy_len;
}

static ssize_t memfd_write(fd_t *fd, const void *buf, uint64_t offset,
                           uint64_t len) {
    void *data = fd->node->handle;

    struct memfd_ctx *ctx = data;
    if (offset + len > ctx->len) {
        size_t new_size = ctx->len * 2;
        uint8_t *new_data = alloc_frames_bytes(new_size);
        if (!new_data)
            return -ENOMEM;
        memcpy(new_data, ctx->data, ctx->len);
        free_frames_bytes(ctx->data, ctx->len);
        ctx->data = new_data;
        ctx->len = new_size;
    }
    memcpy(ctx->data + offset, buf, len);
    ctx->node->size = ctx->len;
    return len;
}

bool memfd_close(vfs_node_t node) {
    struct memfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return true;

    if (--ctx->refcount == 0) {
        spin_lock(&ctx->lock);

        free_frames_bytes(ctx->data, ctx->len);

        spin_unlock(&ctx->lock);

        ctx->node->handle = NULL;
        free(ctx);

        return true;
    } else {
        return false;
    }
}

int memfd_stat(vfs_node_t node) {
    struct memfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return -EINVAL;
    node->size = ctx->len;
    return 0;
}

void memfd_resize(vfs_node_t node, uint64_t size) {
    if (size == 0)
        return;

    struct memfd_ctx *ctx = node ? node->handle : NULL;
    if (!ctx)
        return;

    spin_lock(&ctx->lock);
    uint8_t *new_data = alloc_frames_bytes(size);
    memcpy(new_data, ctx->data, MIN(size, ctx->len));
    free_frames_bytes(ctx->data, ctx->len);
    ctx->data = new_data;
    ctx->len = size;
    spin_unlock(&ctx->lock);
}

void *memfd_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
                size_t flags) {
    if ((flags & MAP_TYPE) == MAP_PRIVATE) {
        return general_map(file, (uint64_t)addr, size, prot, flags, offset);
    }

    struct memfd_ctx *ctx = file->node->handle;

    map_page_range(get_current_page_dir(true), (uint64_t)addr,
                   virt_to_phys((uint64_t)ctx->data + offset), size,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

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
    if ((flags & MFD_HUGETLB)) {
        return -EINVAL;
    }

    if ((flags & MFD_NOEXEC_SEAL) || (flags & MFD_EXEC)) {
        return -EINVAL;
    }

    struct memfd_ctx *ctx = malloc(sizeof(struct memfd_ctx));
    if (!ctx)
        return -ENOMEM;
    strncpy(ctx->name, name, 63);
    ctx->name[63] = '\0';
    ctx->len = DEFAULT_PAGE_SIZE;
    ctx->data = alloc_frames_bytes(ctx->len);
    memset(ctx->data, 0, ctx->len);
    ctx->flags = flags;
    ctx->refcount = 1;
    ctx->lock.lock = 0;

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
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

        fd_t *new_fd = malloc(sizeof(fd_t));
        if (!new_fd) {
            ret = -ENOMEM;
            fd = -1;
            break;
        }

        memset(new_fd, 0, sizeof(fd_t));
        new_fd->node = node;
        new_fd->offset = 0;
        new_fd->flags = O_RDWR | ((flags & MFD_CLOEXEC) ? O_CLOEXEC : 0);
        new_fd->close_on_exec = !!(flags & MFD_CLOEXEC);
        current_task->fd_info->fds[fd] = new_fd;
        procfs_on_open_file(current_task, fd);
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
