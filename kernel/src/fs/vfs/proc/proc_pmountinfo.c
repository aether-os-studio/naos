#include <fs/vfs/proc/proc.h>
#include <task/task.h>
#include <libs/string_builder.h>

extern struct llist_header mount_points;

extern int procfs_mount_point_count;

char *proc_gen_mountinfo_file(task_t *task, size_t *context_len) {
    // TODO: namespace
    string_builder_t *builder = create_string_builder(1024);
    struct mount_point *mnt, *tmp;
    llist_for_each(mnt, tmp, &mount_points, node) {
        vfs_node_t node = mnt->dir;
        char *mount_path = vfs_get_fullpath(node);
        string_builder_append(
            builder, "%d %d %d:%d %s %s rw - %s %s rw\n", node->fsid,
            node->parent ? node->parent->fsid : node->fsid,
            (node->rdev >> 8) & 0xFF, node->rdev & 0xFF, "/", mount_path,
            all_fs[node->fsid]->name, mnt->devname);
        free(mount_path);
    }
    char *data = builder->data;
    *context_len = builder->size;
    free(builder);
    return data;
}

size_t proc_pmountinfo_stat(proc_handle_t *handle) {
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }
    size_t content_len = 0;
    char *content = proc_gen_mountinfo_file(task, &content_len);
    free(content);
    return content_len;
}

int proc_pmountinfo_poll(proc_handle_t *handle, int events) {
    int revents = 0;
    if (events)
        revents |= EPOLLIN;
    return revents;
}

size_t proc_pmountinfo_read(proc_handle_t *handle, void *addr, size_t offset,
                            size_t size) {
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }
    size_t content_len = 0;
    char *content = proc_gen_mountinfo_file(task, &content_len);
    if (offset >= content_len) {
        free(content);
        return 0;
    }
    content_len = MIN(content_len, offset + size);
    size_t to_copy = MIN(content_len, size);
    memcpy(addr, content + offset, to_copy);
    free(content);
    ((char *)addr)[to_copy] = '\0';
    return to_copy;
}
