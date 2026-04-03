#include <fs/proc/proc.h>
#include <task/task.h>
#include <libs/string_builder.h>

static char *proc_gen_mountinfo_file(task_t *task, size_t *content_len) {
    string_builder_t *builder = create_string_builder(256);
    task_mount_namespace_t *mnt_ns =
        (task && task->nsproxy) ? task->nsproxy->mnt_ns : NULL;
    const char *fs_name = "unknown";
    unsigned int mnt_id = 0;
    dev64_t dev = 0;

    if (!builder) {
        *content_len = 0;
        return NULL;
    }

    if (mnt_ns && mnt_ns->root && mnt_ns->root->mnt_sb) {
        if (mnt_ns->root->mnt_sb->s_type && mnt_ns->root->mnt_sb->s_type->name)
            fs_name = mnt_ns->root->mnt_sb->s_type->name;
        mnt_id = mnt_ns->root->mnt_id;
        dev = mnt_ns->root->mnt_sb->s_dev;
    }

    string_builder_append(builder, "%u %u %u:%u / / rw - %s none rw\n", mnt_id,
                          mnt_id, (unsigned int)((dev >> 8) & 0xFF),
                          (unsigned int)(dev & 0xFF), fs_name);

    *content_len = builder->size;
    char *data = builder->data;
    free(builder);
    return data;
}

size_t proc_pmountinfo_stat(proc_handle_t *handle) {
    task_t *task = handle && handle->task ? handle->task : current_task;
    size_t content_len = 0;
    char *content = proc_gen_mountinfo_file(task, &content_len);
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
    char *content = proc_gen_mountinfo_file(task, &content_len);

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
