#include <fs/vfs/vfs.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

static int fsfd_id = 0;
static int mntfd_id = 0;

/* FSMOUNT flags */
#define FSMOUNT_CLOEXEC 0x00000001

/* Mount attributes for fsmount */
#define MOUNT_ATTR_RDONLY 0x00000001
#define MOUNT_ATTR_NOSUID 0x00000002
#define MOUNT_ATTR_NODEV 0x00000004
#define MOUNT_ATTR_NOEXEC 0x00000008
#define MOUNT_ATTR_RELATIME 0x00000000
#define MOUNT_ATTR_NOATIME 0x00000010
#define MOUNT_ATTR_STRICTATIME 0x00000020
#define MOUNT_ATTR_NODIRATIME 0x00000080
#define MOUNT_ATTR_NOSYMFOLLOW 0x00200000

/* move_mount flags */
#define MOVE_MOUNT_F_SYMLINKS 0x00000001
#define MOVE_MOUNT_F_AUTOMOUNTS 0x00000002
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define MOVE_MOUNT_T_SYMLINKS 0x00000010
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#define MOVE_MOUNT_SET_GROUP 0x00000100
#define MOVE_MOUNT_BENEATH 0x00000200

/* FS context state */
#define FC_STATE_INIT 0    /* Context created but not configured */
#define FC_STATE_CONFIG 1  /* Being configured */
#define FC_STATE_CREATED 2 /* Superblock created (FSCONFIG_CMD_CREATE done) */
#define FC_STATE_MOUNTED 3 /* Already mounted via fsmount */

typedef struct fs_context {
    fs_t *fs;               /* Filesystem type */
    char *source;           /* Source device/path */
    char *data;             /* Mount data/options string */
    uint64_t mount_flags;   /* MS_* mount flags */
    uint64_t attr_flags;    /* MOUNT_ATTR_* flags */
    int state;              /* Current state of the context */
    vfs_node_t source_node; /* Resolved source node (if any) */
    uint64_t source_dev;    /* Source device number */
} fs_context_t;

/*
 * Mount handle - represents a "detached" mount that hasn't been attached yet.
 * Unlike Linux, we don't actually mount anything until move_mount is called.
 * This handle just stores the information needed to perform the mount.
 */
typedef struct mount_handle {
    fs_t *fs;             /* Filesystem type */
    char *source;         /* Source device/path (copied) */
    uint64_t mount_flags; /* Mount flags */
    uint64_t dev;         /* Device number */
    bool attached;        /* Whether this mount has been attached */
} mount_handle_t;

/* Convert MOUNT_ATTR_* to MS_* flags */
static uint64_t attr_flags_to_ms_flags(uint64_t attr_flags) {
    uint64_t ms_flags = 0;

    if (attr_flags & MOUNT_ATTR_RDONLY)
        ms_flags |= MS_RDONLY;
    if (attr_flags & MOUNT_ATTR_NOSUID)
        ms_flags |= MS_NOSUID;
    if (attr_flags & MOUNT_ATTR_NODEV)
        ms_flags |= MS_NODEV;
    if (attr_flags & MOUNT_ATTR_NOEXEC)
        ms_flags |= MS_NOEXEC;
    if (attr_flags & MOUNT_ATTR_NOATIME)
        ms_flags |= MS_NOATIME;
    if (attr_flags & MOUNT_ATTR_STRICTATIME)
        ms_flags |= MS_STRICTATIME;
    if (attr_flags & MOUNT_ATTR_NODIRATIME)
        ms_flags |= MS_NODIRATIME;
    if (attr_flags & MOUNT_ATTR_NOSYMFOLLOW)
        ms_flags |= MS_NOSYMFOLLOW;

    return ms_flags;
}

uint64_t sys_fsopen(const char *fsname_user, unsigned int flags) {
    char fsname[256];
    if (copy_from_user_str(fsname, fsname_user, sizeof(fsname)))
        return (uint64_t)-EFAULT;

    fs_context_t *handle = NULL;

    for (int fsid = 1; all_fs[fsid]; fsid++) {
        fs_t *fs = all_fs[fsid];
        if (!strcmp(fs->name, fsname)) {
            handle = malloc(sizeof(fs_context_t));
            if (!handle)
                return (uint64_t)-ENOMEM;
            memset(handle, 0, sizeof(fs_context_t));
            handle->fs = all_fs[fsid];
            handle->source = NULL;
            handle->data = NULL;
            handle->mount_flags = 0;
            handle->attr_flags = 0;
            handle->state = FC_STATE_INIT;
            handle->source_node = NULL;
            handle->source_dev = 0;
            goto found;
        }
    }

    return (uint64_t)-ENOENT;

found:;
    int fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++) {
        if (!current_task->fd_info->fds[i]) {
            fd = i;
            break;
        }
    }

    if (fd == -1) {
        free(handle);
        return (uint64_t)-EMFILE;
    }

    vfs_node_t node = vfs_node_alloc(NULL, NULL);
    if (!node) {
        free(handle);
        return (uint64_t)-ENOMEM;
    }
    node->refcount++;
    node->mode = 0700;
    node->type = file_stream;
    node->fsid = fsfd_id;
    node->handle = handle;

    current_task->fd_info->fds[fd] = malloc(sizeof(fd_t));
    if (!current_task->fd_info->fds[fd]) {
        vfs_free(node);
        free(handle);
        return (uint64_t)-ENOMEM;
    }
    current_task->fd_info->fds[fd]->node = node;
    current_task->fd_info->fds[fd]->offset = 0;
    current_task->fd_info->fds[fd]->flags = flags;

    return fd;
}

uint64_t sys_statfs(const char *path, struct statfs *buf) {
    vfs_node_t node = vfs_open(path);
    if (!node)
        return -ENOENT;

    if (node->fsid > (sizeof(all_fs) / sizeof(all_fs[0])))
        return -EINVAL;

    fs_t *fs = all_fs[node->fsid];
    if (!fs)
        return -ENOENT;

    buf->f_type = fs->magic;

    return 0;
}

uint64_t sys_fstatfs(int fd, struct statfs *buf) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    fd_t *f = current_task->fd_info->fds[fd];

    fs_t *fs = all_fs[f->node->fsid];
    if (!fs)
        return -ENOENT;

    buf->f_type = fs->magic;

    return 0;
}

/* Helper to set a boolean flag option */
static int fsconfig_set_flag(fs_context_t *ctx, const char *key) {
    /* Common mount flags */
    if (!strcmp(key, "ro") || !strcmp(key, "rdonly")) {
        ctx->mount_flags |= MS_RDONLY;
        return 0;
    }
    if (!strcmp(key, "rw")) {
        ctx->mount_flags &= ~MS_RDONLY;
        return 0;
    }
    if (!strcmp(key, "nosuid")) {
        ctx->mount_flags |= MS_NOSUID;
        return 0;
    }
    if (!strcmp(key, "suid")) {
        ctx->mount_flags &= ~MS_NOSUID;
        return 0;
    }
    if (!strcmp(key, "nodev")) {
        ctx->mount_flags |= MS_NODEV;
        return 0;
    }
    if (!strcmp(key, "dev")) {
        ctx->mount_flags &= ~MS_NODEV;
        return 0;
    }
    if (!strcmp(key, "noexec")) {
        ctx->mount_flags |= MS_NOEXEC;
        return 0;
    }
    if (!strcmp(key, "exec")) {
        ctx->mount_flags &= ~MS_NOEXEC;
        return 0;
    }
    if (!strcmp(key, "sync") || !strcmp(key, "synchronous")) {
        ctx->mount_flags |= MS_SYNCHRONOUS;
        return 0;
    }
    if (!strcmp(key, "async")) {
        ctx->mount_flags &= ~MS_SYNCHRONOUS;
        return 0;
    }
    if (!strcmp(key, "remount")) {
        ctx->mount_flags |= MS_REMOUNT;
        return 0;
    }
    if (!strcmp(key, "mand") || !strcmp(key, "mandlock")) {
        ctx->mount_flags |= MS_MANDLOCK;
        return 0;
    }
    if (!strcmp(key, "nomand")) {
        ctx->mount_flags &= ~MS_MANDLOCK;
        return 0;
    }
    if (!strcmp(key, "dirsync")) {
        ctx->mount_flags |= MS_DIRSYNC;
        return 0;
    }
    if (!strcmp(key, "nosymfollow")) {
        ctx->mount_flags |= MS_NOSYMFOLLOW;
        return 0;
    }
    if (!strcmp(key, "symfollow")) {
        ctx->mount_flags &= ~MS_NOSYMFOLLOW;
        return 0;
    }
    if (!strcmp(key, "noatime")) {
        ctx->mount_flags |= MS_NOATIME;
        return 0;
    }
    if (!strcmp(key, "atime")) {
        ctx->mount_flags &= ~MS_NOATIME;
        return 0;
    }
    if (!strcmp(key, "nodiratime")) {
        ctx->mount_flags |= MS_NODIRATIME;
        return 0;
    }
    if (!strcmp(key, "diratime")) {
        ctx->mount_flags &= ~MS_NODIRATIME;
        return 0;
    }
    if (!strcmp(key, "relatime")) {
        ctx->mount_flags |= MS_RELATIME;
        return 0;
    }
    if (!strcmp(key, "norelatime")) {
        ctx->mount_flags &= ~MS_RELATIME;
        return 0;
    }
    if (!strcmp(key, "strictatime")) {
        ctx->mount_flags |= MS_STRICTATIME;
        return 0;
    }
    if (!strcmp(key, "lazytime")) {
        ctx->mount_flags |= MS_LAZYTIME;
        return 0;
    }
    if (!strcmp(key, "nolazytime")) {
        ctx->mount_flags &= ~MS_LAZYTIME;
        return 0;
    }
    if (!strcmp(key, "silent")) {
        ctx->mount_flags |= MS_SILENT;
        return 0;
    }
    if (!strcmp(key, "loud")) {
        ctx->mount_flags &= ~MS_SILENT;
        return 0;
    }

    /* Unknown flag - may be filesystem specific, ignore for now */
    return 0;
}

/* Helper to set a string option */
static int fsconfig_set_string(fs_context_t *ctx, const char *key,
                               const char *value) {
    if (!strcmp(key, "source")) {
        if (ctx->source)
            free(ctx->source);
        ctx->source = strdup(value);
        if (!ctx->source)
            return -ENOMEM;

        /* Try to resolve the source to get device number */
        vfs_node_t source_node = vfs_open(value);
        if (source_node) {
            ctx->source_node = source_node;
            ctx->source_dev = source_node->rdev;
        }
        return 0;
    }

    /* Handle mount options/data */
    if (!strcmp(key, "data") || !strcmp(key, "options")) {
        if (ctx->data)
            free(ctx->data);
        ctx->data = strdup(value);
        if (!ctx->data)
            return -ENOMEM;
        return 0;
    }

    /* For unknown string options, append to data */
    if (value && strlen(value) > 0) {
        char opt_buf[512];
        snprintf(opt_buf, sizeof(opt_buf), "%s=%s", key, value);

        if (ctx->data) {
            size_t old_len = strlen(ctx->data);
            size_t opt_len = strlen(opt_buf);
            char *new_data = malloc(old_len + opt_len + 2);
            if (!new_data)
                return -ENOMEM;
            strcpy(new_data, ctx->data);
            strcat(new_data, ",");
            strcat(new_data, opt_buf);
            free(ctx->data);
            ctx->data = new_data;
        } else {
            ctx->data = strdup(opt_buf);
            if (!ctx->data)
                return -ENOMEM;
        }
    }

    return 0;
}

/* Helper to handle FSCONFIG_CMD_CREATE - validates and prepares for mount */
static int fsconfig_cmd_create(fs_context_t *ctx) {
    if (ctx->state == FC_STATE_CREATED)
        return -EBUSY;

    /* Validate we have a filesystem */
    if (!ctx->fs)
        return -EINVAL;

    /* Mark as created */
    ctx->state = FC_STATE_CREATED;

    return 0;
}

/* Helper to handle FSCONFIG_CMD_RECONFIGURE */
static int fsconfig_cmd_reconfigure(fs_context_t *ctx) {
    if (ctx->state != FC_STATE_CREATED && ctx->state != FC_STATE_MOUNTED)
        return -EINVAL;

    /* Reconfiguration allowed - just return success */
    return 0;
}

uint64_t sys_fsconfig(int fd, uint32_t cmd, const char *key_user,
                      const void *value_user, int aux) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    fd_t *file_descriptor = current_task->fd_info->fds[fd];

    /* Check if this is an fs context fd */
    if (file_descriptor->node->fsid != fsfd_id)
        return -EINVAL;

    fs_context_t *ctx = file_descriptor->node->handle;
    if (!ctx || !ctx->fs)
        return -ENOENT;

    char key[256];
    char value[1024];
    int ret = 0;

    switch (cmd) {
    case FSCONFIG_SET_FLAG:
        /* Set a flag parameter (no value) */
        if (!key_user)
            return -EINVAL;
        if (copy_from_user_str(key, key_user, sizeof(key)))
            return -EFAULT;
        ctx->state = FC_STATE_CONFIG;
        ret = fsconfig_set_flag(ctx, key);
        break;

    case FSCONFIG_SET_STRING:
        /* Set a string parameter */
        if (!key_user)
            return -EINVAL;
        if (copy_from_user_str(key, key_user, sizeof(key)))
            return -EFAULT;
        if (value_user) {
            if (copy_from_user_str(value, value_user, sizeof(value)))
                return -EFAULT;
        } else {
            value[0] = '\0';
        }
        ctx->state = FC_STATE_CONFIG;
        ret = fsconfig_set_string(ctx, key, value);
        break;

    case FSCONFIG_SET_BINARY:
        /* Set a binary blob parameter - treat as string for now */
        if (!key_user)
            return -EINVAL;
        if (copy_from_user_str(key, key_user, sizeof(key)))
            return -EFAULT;
        /* aux contains the length of the binary data */
        if (aux > 0 && value_user) {
            size_t copy_len =
                aux < (int)sizeof(value) - 1 ? aux : sizeof(value) - 1;
            if (copy_from_user(value, value_user, copy_len))
                return -EFAULT;
            value[copy_len] = '\0';
        } else {
            value[0] = '\0';
        }
        ctx->state = FC_STATE_CONFIG;
        ret = fsconfig_set_string(ctx, key, value);
        break;

    case FSCONFIG_SET_PATH:
    case FSCONFIG_SET_PATH_EMPTY:
        /* Set parameter by path - value is a path, aux is dirfd */
        if (!key_user)
            return -EINVAL;
        if (copy_from_user_str(key, key_user, sizeof(key)))
            return -EFAULT;
        if (value_user) {
            if (copy_from_user_str(value, value_user, sizeof(value)))
                return -EFAULT;
        } else if (cmd == FSCONFIG_SET_PATH_EMPTY) {
            /* Empty path with dirfd - resolve from dirfd */
            if (aux < 0 || aux >= MAX_FD_NUM ||
                !current_task->fd_info->fds[aux])
                return -EBADF;
            /* For now just use empty string */
            value[0] = '\0';
        } else {
            return -EINVAL;
        }
        ctx->state = FC_STATE_CONFIG;

        /* Handle path-based parameters */
        if (!strcmp(key, "source")) {
            /* Resolve path relative to dirfd if needed */
            char *resolved = at_resolve_pathname(aux, value);
            if (resolved) {
                ret = fsconfig_set_string(ctx, key, resolved);
            } else {
                ret = fsconfig_set_string(ctx, key, value);
            }
        } else {
            ret = fsconfig_set_string(ctx, key, value);
        }
        break;

    case FSCONFIG_SET_FD:
        /* Set parameter by file descriptor */
        if (!key_user)
            return -EINVAL;
        if (copy_from_user_str(key, key_user, sizeof(key)))
            return -EFAULT;
        /* aux contains the file descriptor */
        if (aux < 0 || aux >= MAX_FD_NUM || !current_task->fd_info->fds[aux])
            return -EBADF;
        ctx->state = FC_STATE_CONFIG;

        /* Handle fd-based source */
        if (!strcmp(key, "source")) {
            fd_t *source_fd = current_task->fd_info->fds[aux];
            ctx->source_node = source_fd->node;
            ctx->source_dev = source_fd->node->rdev;
            /* Generate a name for logging purposes */
            if (ctx->source)
                free(ctx->source);
            if (source_fd->node->name) {
                ctx->source = strdup(source_fd->node->name);
            } else {
                char buf[32];
                snprintf(buf, sizeof(buf), "fd:%d", aux);
                ctx->source = strdup(buf);
            }
            ret = 0;
        } else {
            ret = -EOPNOTSUPP;
        }
        break;

    case FSCONFIG_CMD_CREATE:
        /* Create the superblock */
        ret = fsconfig_cmd_create(ctx);
        break;

    case FSCONFIG_CMD_CREATE_EXCL:
        /* Create new superblock, fail if reusing */
        if (ctx->state == FC_STATE_CREATED || ctx->state == FC_STATE_MOUNTED)
            return -EBUSY;
        ret = fsconfig_cmd_create(ctx);
        break;

    case FSCONFIG_CMD_RECONFIGURE:
        /* Reconfigure the superblock */
        ret = fsconfig_cmd_reconfigure(ctx);
        break;

    default:
        ret = -EOPNOTSUPP;
        break;
    }

    return ret;
}

/*
 * sys_fsmount - Create a mount fd from an fs context
 *
 * This does NOT actually mount the filesystem. It creates a "detached mount"
 * represented by a file descriptor. The actual mounting happens when
 * move_mount() is called to attach this mount to a location in the filesystem.
 */
uint64_t sys_fsmount(int fd, uint32_t flags, uint32_t attr_flags) {
    if (fd < 0 || fd >= MAX_FD_NUM || !current_task->fd_info->fds[fd])
        return -EBADF;

    fd_t *file_descriptor = current_task->fd_info->fds[fd];

    /* Check if this is an fs context fd */
    if (file_descriptor->node->fsid != fsfd_id)
        return -EINVAL;

    fs_context_t *ctx = file_descriptor->node->handle;
    if (!ctx || !ctx->fs)
        return -ENOENT;

    /* Must have called FSCONFIG_CMD_CREATE first */
    if (ctx->state != FC_STATE_CREATED)
        return -EINVAL;

    /* Combine mount flags from context with attr_flags */
    uint64_t combined_flags =
        ctx->mount_flags | attr_flags_to_ms_flags(attr_flags);

    /* Create mount handle - stores info for later mounting */
    mount_handle_t *mnt_handle = malloc(sizeof(mount_handle_t));
    if (!mnt_handle)
        return -ENOMEM;

    mnt_handle->fs = ctx->fs;
    mnt_handle->source = ctx->source ? strdup(ctx->source) : NULL;
    mnt_handle->mount_flags = combined_flags;
    mnt_handle->dev = ctx->source_dev;
    mnt_handle->attached = false;

    /* Allocate new fd for the mount */
    int mnt_fd = -1;
    for (int i = 3; i < MAX_FD_NUM; i++) {
        if (!current_task->fd_info->fds[i]) {
            mnt_fd = i;
            break;
        }
    }

    if (mnt_fd == -1) {
        if (mnt_handle->source)
            free(mnt_handle->source);
        free(mnt_handle);
        return -EMFILE;
    }

    /* Create vfs node for mount fd */
    vfs_node_t mnt_node = vfs_node_alloc(NULL, NULL);
    if (!mnt_node) {
        if (mnt_handle->source)
            free(mnt_handle->source);
        free(mnt_handle);
        return -ENOMEM;
    }

    mnt_node->refcount++;
    mnt_node->mode = 0700;
    mnt_node->type = file_stream;
    mnt_node->fsid = mntfd_id;
    mnt_node->handle = mnt_handle;

    current_task->fd_info->fds[mnt_fd] = malloc(sizeof(fd_t));
    if (!current_task->fd_info->fds[mnt_fd]) {
        vfs_free(mnt_node);
        if (mnt_handle->source)
            free(mnt_handle->source);
        free(mnt_handle);
        return -ENOMEM;
    }

    current_task->fd_info->fds[mnt_fd]->node = mnt_node;
    current_task->fd_info->fds[mnt_fd]->offset = 0;
    current_task->fd_info->fds[mnt_fd]->flags =
        (flags & FSMOUNT_CLOEXEC) ? O_CLOEXEC : 0;

    /* Mark context as mounted */
    ctx->state = FC_STATE_MOUNTED;

    return mnt_fd;
}

/*
 * sys_move_mount - Attach a detached mount to the filesystem tree
 *
 * When from_dfd is a mount fd (created by fsmount) with
 * MOVE_MOUNT_F_EMPTY_PATH, this actually performs the vfs_mount() to mount the
 * filesystem at the target.
 */
uint64_t sys_move_mount(int from_dfd, const char *from_pathname_user,
                        int to_dfd, const char *to_pathname_user,
                        uint32_t flags) {
    char from_pathname[512];
    char to_pathname[512];

    /* Handle empty path flags */
    bool from_empty = (flags & MOVE_MOUNT_F_EMPTY_PATH) != 0;
    bool to_empty = (flags & MOVE_MOUNT_T_EMPTY_PATH) != 0;

    if (!from_empty) {
        if (!from_pathname_user)
            return -EINVAL;
        if (copy_from_user_str(from_pathname, from_pathname_user,
                               sizeof(from_pathname)))
            return -EFAULT;
    } else {
        from_pathname[0] = '\0';
    }

    if (!to_empty) {
        if (!to_pathname_user)
            return -EINVAL;
        if (copy_from_user_str(to_pathname, to_pathname_user,
                               sizeof(to_pathname)))
            return -EFAULT;
    } else {
        to_pathname[0] = '\0';
    }

    mount_handle_t *mnt_handle = NULL;
    vfs_node_t source_mount = NULL;

    /* Resolve the source */
    if (from_empty && from_dfd >= 0 && from_dfd < MAX_FD_NUM &&
        current_task->fd_info->fds[from_dfd]) {
        fd_t *from_fd = current_task->fd_info->fds[from_dfd];

        /* Check if from_dfd is a mount fd (created by fsmount) */
        if (from_fd->node->fsid == mntfd_id) {
            mnt_handle = from_fd->node->handle;
            if (!mnt_handle || mnt_handle->attached)
                return -EINVAL;
        } else {
            /* It's a regular fd pointing to a mount point */
            source_mount = from_fd->node;
            if (!source_mount->root || source_mount->root != source_mount)
                return -EINVAL;
        }
    } else {
        /* Resolve path to get existing mount */
        char *resolved = at_resolve_pathname(from_dfd, from_pathname);
        source_mount = vfs_open(resolved ? resolved : from_pathname);
        if (!source_mount)
            return -ENOENT;

        /* Must be a mount root */
        if (!source_mount->root || source_mount->root != source_mount)
            return -EINVAL;
    }

    /* Resolve the target directory */
    vfs_node_t target_dir = NULL;
    if (to_empty && to_dfd >= 0 && to_dfd < MAX_FD_NUM &&
        current_task->fd_info->fds[to_dfd]) {
        target_dir = current_task->fd_info->fds[to_dfd]->node;
    } else {
        char *resolved = at_resolve_pathname(to_dfd, to_pathname);
        target_dir = vfs_open(resolved ? resolved : to_pathname);
    }

    if (!target_dir)
        return -ENOENT;

    if (!(target_dir->type & file_dir))
        return -ENOTDIR;

    /*
     * Case 1: Attaching a detached mount (from fsmount)
     * This is where we actually call vfs_mount()
     */
    if (mnt_handle) {
        int ret = vfs_mount(mnt_handle->dev, target_dir, mnt_handle->fs->name);
        if (ret < 0)
            return ret;

        mnt_handle->attached = true;
        return 0;
    }

    /*
     * Case 2: Moving an existing mount to a new location
     * Similar to MS_MOVE in sys_mount
     */
    if (source_mount) {
        uint64_t dev = source_mount->rdev;
        uint32_t fsid = source_mount->fsid;

        if (fsid == 0 || fsid >= 256 || !all_fs[fsid])
            return -EINVAL;

        const char *fs_name = all_fs[fsid]->name;

        /* Get path of old mount for unmounting */
        char *old_path = vfs_get_fullpath(source_mount);
        if (!old_path)
            return -ENOMEM;

        /* Unmount from old location */
        int ret = vfs_unmount(old_path);
        free(old_path);
        if (ret < 0)
            return ret;

        /* Mount at new location */
        ret = vfs_mount(dev, target_dir, fs_name);
        if (ret < 0)
            return ret;

        return 0;
    }

    return -EINVAL;
}

ssize_t fsfdfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    return -ENOMSG;
}

bool fsfdfs_close(void *current) {
    fs_context_t *ctx = current;
    if (!ctx)
        return true;

    if (ctx->source)
        free(ctx->source);
    if (ctx->data)
        free(ctx->data);
    free(ctx);

    return true;
}

bool mntfd_close(void *current) {
    mount_handle_t *mnt = current;
    if (!mnt)
        return true;

    /* Free source string if allocated */
    if (mnt->source)
        free(mnt->source);

    free(mnt);
    return true;
}

static int dummy() { return 0; }

static struct vfs_callback fsfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)fsfdfs_close,
    .read = (vfs_read_t)fsfdfs_read,
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
    .poll = (vfs_poll_t)dummy,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

static struct vfs_callback mntfd_callbacks = {
    .mount = (vfs_mount_t)dummy,
    .unmount = (vfs_unmount_t)dummy,
    .open = (vfs_open_t)dummy,
    .close = (vfs_close_t)mntfd_close,
    .read = (vfs_read_t)fsfdfs_read,
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
    .poll = (vfs_poll_t)dummy,
    .resize = (vfs_resize_t)dummy,

    .free_handle = vfs_generic_free_handle,
};

fs_t fsfd_fs = {
    .name = "fsfd",
    .magic = 0,
    .callback = &fsfd_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

fs_t mntfd_fs = {
    .name = "mntfd",
    .magic = 0,
    .callback = &mntfd_callbacks,
    .flags = FS_FLAGS_HIDDEN,
};

void fsfdfs_init() {
    fsfd_id = vfs_regist(&fsfd_fs);
    mntfd_id = vfs_regist(&mntfd_fs);
}
