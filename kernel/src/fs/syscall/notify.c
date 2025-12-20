#include <fs/vfs/vfs.h>
#include <fs/vfs/proc.h>
#include <task/task.h>

static int notifyfs_id = 0;

static int dummy() { return 0; }

static int notifyfs_poll(void *file, size_t events) { return 0; }

static struct vfs_callback notifyfs_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)dummy,
    .read = (vfs_read_t)dummy,
    .write = (vfs_write_t)dummy,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .chown = (vfs_chown_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .delete = (vfs_del_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .poll = (vfs_poll_t)notifyfs_poll,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

fs_t notifyfs_fs = {
    .name = "notifyfs",
    .magic = 0,
    .callback = &notifyfs_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

uint64_t sys_inotify_init1(uint64_t flags) {
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++) {
        if (!current_task->fd_info->fds[i]) {
            fd = i;
            break;
        }
    }

    if (fd == -1) {
        return (uint64_t)-EMFILE;
    }

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    node->type = file_none;
    node->fsid = notifyfs_id;
    node->handle = NULL;
    node->refcount++;
    node->size = 0;
    current_task->fd_info->fds[fd] = malloc(sizeof(fd_t));
    current_task->fd_info->fds[fd]->node = node;
    current_task->fd_info->fds[fd]->flags = 0;
    procfs_on_open_file(current_task, fd);

    return fd;
}

uint64_t sys_inotify_init() { return sys_inotify_init1(0); }

void notifyfs_init() { notifyfs_id = vfs_regist(&notifyfs_fs); }
