#include <fs/vfs/vfs.h>
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

bool memfd_close(void *current) {
    struct memfd_ctx *ctx = current;

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

int memfd_stat(void *file, vfs_node_t node) {
    struct memfd_ctx *ctx = file;
    node->size = ctx->len;

    return 0;
}

void memfd_resize(void *current, uint64_t size) {
    if (size == 0)
        return;

    struct memfd_ctx *ctx = current;

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
    struct memfd_ctx *ctx = file->node->handle;

    map_page_range(
        get_current_page_dir(true), (uint64_t)addr,
        translate_address(get_current_page_dir(false), (uint64_t)ctx->data),
        size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    return addr;
}

static int dummy() { return 0; }

static struct vfs_callback callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)memfd_close,
    .read = (vfs_read_t)memfd_read,
    .write = (vfs_write_t)memfd_write,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .map = (vfs_mapfile_t)memfd_map,
    .stat = (vfs_stat_t)memfd_stat,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)dummy,
    .resize = (vfs_resize_t)memfd_resize,

    .free_handle = vfs_generic_free_handle,
};

#define MFD_CLOEXEC 0x0001U
#define MFD_ALLOW_SEALING 0x0002U
#define MFD_HUGETLB 0x0004U

static int memfd_idx = 0;

uint64_t sys_memfd_create(const char *name, unsigned int flags) {
    struct memfd_ctx *ctx = malloc(sizeof(struct memfd_ctx));
    strncpy(ctx->name, name, 63);
    ctx->name[63] = '\0';
    ctx->len = DEFAULT_PAGE_SIZE;
    ctx->data = alloc_frames_bytes(ctx->len);
    ctx->flags = flags;
    ctx->refcount = 1;
    ctx->lock.lock = 0;

    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++) {
        if (!current_task->fd_info->fds[i]) {
            fd = i;
            break;
        }
    }

    char fn[16];
    sprintf(fn, "memfd%d", memfd_idx++);
    vfs_node_t node = vfs_node_alloc(NULL, fn);
    node->type = file_none;
    node->fsid = memfd_fsid;
    node->handle = ctx;
    node->refcount++;
    node->size = 0;
    current_task->fd_info->fds[fd] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[fd]->node = node;
    current_task->fd_info->fds[fd]->flags =
        (flags & MFD_CLOEXEC) ? O_CLOEXEC : 0;

    ctx->node = node;

    return fd;
}

fs_t memfdfs = {
    .name = "memfdfs",
    .magic = 0,
    .callback = &callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

void memfd_init() { memfd_fsid = vfs_regist(&memfdfs); }
