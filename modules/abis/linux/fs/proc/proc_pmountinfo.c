#include <fs/proc/proc.h>
#include <task/task.h>
#include <libs/string_builder.h>

static void procfs_append_mount_opts(string_builder_t *builder,
                                     unsigned long flags) {
    string_builder_append(builder, "%s",
                          (flags & VFS_MNT_READONLY) ? "ro" : "rw");
    if (flags & VFS_MNT_NOSUID)
        string_builder_append(builder, ",nosuid");
    if (flags & VFS_MNT_NODEV)
        string_builder_append(builder, ",nodev");
    if (flags & VFS_MNT_NOEXEC)
        string_builder_append(builder, ",noexec");
    if (flags & VFS_MNT_NOSYMFOLLOW)
        string_builder_append(builder, ",nosymfollow");
}

static char *procfs_mount_path(struct vfs_mount *mnt,
                               const struct vfs_path *ns_root) {
    struct vfs_path path = {0};

    if (!mnt || !ns_root || !ns_root->mnt || !ns_root->dentry)
        return strdup("/");
    if (mnt == ns_root->mnt)
        return strdup("/");

    path.mnt = mnt->mnt_parent;
    path.dentry = mnt->mnt_mountpoint;
    return vfs_path_to_string(&path, ns_root);
}

static bool procfs_append_single_mount(string_builder_t *builder,
                                       struct vfs_mount *mnt,
                                       const struct vfs_path *ns_root,
                                       bool mountinfo) {
    const char *fs_name = "unknown";
    const char *source = "none";
    char *mountpoint;
    unsigned int parent_id;
    dev64_t dev = 0;

    if (!builder || !mnt || !ns_root)
        return false;

    if (mnt->mnt_sb) {
        dev = mnt->mnt_sb->s_dev;
        if (mnt->mnt_sb->s_type && mnt->mnt_sb->s_type->name)
            fs_name = mnt->mnt_sb->s_type->name;
    }

    mountpoint = procfs_mount_path(mnt, ns_root);
    if (!mountpoint)
        return false;

    parent_id = mnt == ns_root->mnt
                    ? mnt->mnt_id
                    : (mnt->mnt_parent ? mnt->mnt_parent->mnt_id : mnt->mnt_id);

    if (mountinfo) {
        string_builder_append(builder, "%u %u %u:%u / %s ", mnt->mnt_id,
                              parent_id, (unsigned int)((dev >> 8) & 0xFF),
                              (unsigned int)(dev & 0xFF), mountpoint);
        procfs_append_mount_opts(builder, mnt->mnt_flags);
        if (vfs_mount_is_shared(mnt))
            string_builder_append(builder, " shared:%u",
                                  vfs_mount_peer_group_id(mnt));
        else if (mnt->mnt_propagation == VFS_MNT_PROP_SLAVE &&
                 vfs_mount_master_group_id(mnt) != 0)
            string_builder_append(builder, " master:%u",
                                  vfs_mount_master_group_id(mnt));
        else if (mnt->mnt_propagation == VFS_MNT_PROP_UNBINDABLE)
            string_builder_append(builder, " unbindable");
        string_builder_append(builder, " - %s %s ", fs_name, source);
        procfs_append_mount_opts(builder, mnt->mnt_flags);
        string_builder_append(builder, "\n");
    } else {
        string_builder_append(builder, "%s %s %s ", source, mountpoint,
                              fs_name);
        procfs_append_mount_opts(builder, mnt->mnt_flags);
        string_builder_append(builder, " 0 0\n");
    }

    free(mountpoint);
    return true;
}

static bool procfs_append_mount_tree(string_builder_t *builder,
                                     struct vfs_mount *mnt,
                                     const struct vfs_path *ns_root,
                                     bool mountinfo) {
    struct vfs_mount *child, *tmp;

    if (!procfs_append_single_mount(builder, mnt, ns_root, mountinfo))
        return false;

    llist_for_each(child, tmp, &mnt->mnt_mounts, mnt_child) {
        if (!procfs_append_mount_tree(builder, child, ns_root, mountinfo))
            return false;
    }
    return true;
}

char *procfs_generate_mount_table(task_t *task, bool mountinfo,
                                  size_t *content_len) {
    string_builder_t *builder = create_string_builder(512);
    struct vfs_mount *root;
    struct vfs_path ns_root = {0};

    if (!builder) {
        *content_len = 0;
        return NULL;
    }

    root = (task && task->nsproxy && task->nsproxy->mnt_ns &&
            task->nsproxy->mnt_ns->root)
               ? task->nsproxy->mnt_ns->root
               : vfs_root_path.mnt;
    if (!root || !root->mnt_root) {
        *content_len = 0;
        char *data = builder->data;
        free(builder);
        return data;
    }

    ns_root.mnt = root;
    ns_root.dentry = root->mnt_root;
    if (!procfs_append_mount_tree(builder, root, &ns_root, mountinfo)) {
        free(builder->data);
        free(builder);
        *content_len = 0;
        return NULL;
    }

    *content_len = builder->size;
    char *data = builder->data;
    free(builder);
    return data;
}

size_t proc_pmountinfo_stat(proc_handle_t *handle) {
    task_t *task = handle && handle->task ? handle->task : current_task;
    size_t content_len = 0;
    char *content = procfs_generate_mount_table(task, true, &content_len);
    free(content);
    return content_len;
}

int proc_pmountinfo_poll(proc_handle_t *handle, int events) {
    (void)handle;
    return (events & EPOLLIN) ? EPOLLIN : 0;
}

size_t proc_pmountinfo_read(proc_handle_t *handle, void *addr, size_t offset,
                            size_t size) {
    task_t *task = handle && handle->task ? handle->task : current_task;
    size_t content_len = 0;
    char *content = procfs_generate_mount_table(task, true, &content_len);

    if (!content)
        return 0;
    if (offset >= content_len) {
        free(content);
        return 0;
    }

    size_t to_copy = MIN(size, content_len - offset);
    memcpy(addr, content + offset, to_copy);
    free(content);
    return to_copy;
}
