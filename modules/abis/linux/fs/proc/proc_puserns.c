#include <fs/proc/proc.h>
#include <task/task.h>
#include <task/ns.h>
#include <libs/string_builder.h>

static char *proc_userns_copy_from_user(const void *addr, size_t size) {
    char *buf;

    if (!addr || !size)
        return strdup("");

    buf = calloc(1, size + 1);
    if (!buf)
        return NULL;
    if (copy_from_user(buf, addr, size)) {
        free(buf);
        return NULL;
    }
    return buf;
}

static char *proc_userns_render_map(task_user_namespace_t *user_ns, bool gid,
                                    size_t *content_len) {
    string_builder_t *builder = create_string_builder(128);
    task_id_map_range_t *ranges;
    size_t count;

    if (!builder || !user_ns || !content_len) {
        if (builder) {
            free(builder->data);
            free(builder);
        }
        if (content_len)
            *content_len = 0;
        return NULL;
    }

    mutex_lock(&user_ns->lock);
    ranges = gid ? user_ns->gid_map : user_ns->uid_map;
    count = gid ? user_ns->gid_map_count : user_ns->uid_map_count;
    for (size_t i = 0; i < count; ++i) {
        string_builder_append(builder, "%u %u %u\n", ranges[i].inside_id,
                              ranges[i].outside_id, ranges[i].length);
    }
    mutex_unlock(&user_ns->lock);

    *content_len = builder->size;
    char *data = builder->data;
    free(builder);
    return data;
}

static int proc_userns_apply_map(task_user_namespace_t *user_ns, bool gid,
                                 task_id_map_range_t *ranges, size_t count,
                                 bool from_helper) {
    int ret = 0;

    if (!user_ns || !ranges || !count || count > TASK_USERNS_MAX_ID_MAPS)
        return -EINVAL;

    mutex_lock(&user_ns->lock);
    if (gid) {
        if (user_ns->gid_map_written) {
            ret = -EPERM;
        } else if (!from_helper && user_ns->level > 0 &&
                   user_ns->setgroups_state != TASK_USERNS_SETGROUPS_DENY) {
            ret = -EPERM;
        } else {
            memcpy(user_ns->gid_map, ranges, count * sizeof(*ranges));
            user_ns->gid_map_count = count;
            user_ns->gid_map_written = true;
        }
    } else {
        if (user_ns->uid_map_written) {
            ret = -EPERM;
        } else {
            memcpy(user_ns->uid_map, ranges, count * sizeof(*ranges));
            user_ns->uid_map_count = count;
            user_ns->uid_map_written = true;
        }
    }
    mutex_unlock(&user_ns->lock);
    return ret;
}

static int proc_userns_parse_u32(char **cursor, uint32_t *value) {
    char *p = cursor ? *cursor : NULL;
    uint64_t parsed = 0;

    if (!p || !value)
        return -EINVAL;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p < '0' || *p > '9')
        return -EINVAL;

    while (*p >= '0' && *p <= '9') {
        parsed = parsed * 10 + (uint64_t)(*p - '0');
        if (parsed > UINT32_MAX)
            return -EINVAL;
        p++;
    }

    *value = (uint32_t)parsed;
    *cursor = p;
    return 0;
}

static ssize_t proc_userns_write_map(proc_handle_t *handle, const void *addr,
                                     size_t offset, size_t size, bool gid) {
    task_t *task = procfs_handle_task_or_current(handle);
    task_user_namespace_t *user_ns = task_user_namespace_of_task(task);
    task_id_map_range_t ranges[TASK_USERNS_MAX_ID_MAPS];
    char *buf;
    char *cursor;
    size_t count = 0;
    int ret;
    bool from_helper;

    if (!user_ns)
        return -EINVAL;
    if (offset != 0)
        return -EINVAL;
    from_helper = handle && handle->task_pid != 0 &&
                  handle->task_pid != current_task->pid;

    buf = proc_userns_copy_from_user(addr, size);
    if (!buf)
        return -EFAULT;

    cursor = buf;
    while (*cursor) {
        uint32_t inside = 0;
        uint32_t outside = 0;
        uint32_t length = 0;

        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n')
            cursor++;
        if (!*cursor)
            break;
        if (count >= TASK_USERNS_MAX_ID_MAPS) {
            free(buf);
            return -EINVAL;
        }

        if (proc_userns_parse_u32(&cursor, &inside) < 0 ||
            proc_userns_parse_u32(&cursor, &outside) < 0 ||
            proc_userns_parse_u32(&cursor, &length) < 0 || length == 0) {
            free(buf);
            return -EINVAL;
        }
        while (*cursor == ' ' || *cursor == '\t')
            cursor++;
        if (*cursor && *cursor != '\n') {
            free(buf);
            return -EINVAL;
        }

        ranges[count++] = (task_id_map_range_t){
            .inside_id = inside, .outside_id = outside, .length = length};
        if (*cursor == '\n')
            cursor++;
    }

    free(buf);
    if (!count)
        return -EINVAL;

    ret = proc_userns_apply_map(user_ns, gid, ranges, count, from_helper);
    return ret < 0 ? ret : (ssize_t)size;
}

static ssize_t proc_userns_write_setgroups(proc_handle_t *handle,
                                           const void *addr, size_t offset,
                                           size_t size) {
    task_t *task = procfs_handle_task_or_current(handle);
    task_user_namespace_t *user_ns = task_user_namespace_of_task(task);
    char *buf;
    char *cursor;
    int ret = 0;

    if (!user_ns)
        return -EINVAL;
    if (offset != 0)
        return -EINVAL;

    buf = proc_userns_copy_from_user(addr, size);
    if (!buf)
        return -EFAULT;

    cursor = buf;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n')
        cursor++;

    mutex_lock(&user_ns->lock);
    if (!strncmp(cursor, "deny", 4)) {
        if (user_ns->gid_map_written)
            ret = -EPERM;
        else
            user_ns->setgroups_state = TASK_USERNS_SETGROUPS_DENY;
    } else if (!strncmp(cursor, "allow", 5)) {
        if (user_ns->setgroups_state == TASK_USERNS_SETGROUPS_DENY)
            ret = -EPERM;
        else
            user_ns->setgroups_state = TASK_USERNS_SETGROUPS_ALLOW;
    } else {
        ret = -EINVAL;
    }
    mutex_unlock(&user_ns->lock);

    free(buf);
    return ret < 0 ? ret : (ssize_t)size;
}

size_t proc_puid_map_stat(proc_handle_t *handle) {
    task_t *task = procfs_handle_task_or_current(handle);
    task_user_namespace_t *user_ns = task_user_namespace_of_task(task);
    size_t content_len = 0;
    char *content = proc_userns_render_map(user_ns, false, &content_len);
    free(content);
    return content_len;
}

size_t proc_puid_map_read(proc_handle_t *handle, void *addr, size_t offset,
                          size_t size) {
    task_t *task = procfs_handle_task_or_current(handle);
    task_user_namespace_t *user_ns = task_user_namespace_of_task(task);
    size_t content_len = 0;
    char *content = proc_userns_render_map(user_ns, false, &content_len);

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

ssize_t proc_puid_map_write(proc_handle_t *handle, const void *addr,
                            size_t offset, size_t size) {
    return proc_userns_write_map(handle, addr, offset, size, false);
}

size_t proc_pgid_map_stat(proc_handle_t *handle) {
    task_t *task = procfs_handle_task_or_current(handle);
    task_user_namespace_t *user_ns = task_user_namespace_of_task(task);
    size_t content_len = 0;
    char *content = proc_userns_render_map(user_ns, true, &content_len);
    free(content);
    return content_len;
}

size_t proc_pgid_map_read(proc_handle_t *handle, void *addr, size_t offset,
                          size_t size) {
    task_t *task = procfs_handle_task_or_current(handle);
    task_user_namespace_t *user_ns = task_user_namespace_of_task(task);
    size_t content_len = 0;
    char *content = proc_userns_render_map(user_ns, true, &content_len);

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

ssize_t proc_pgid_map_write(proc_handle_t *handle, const void *addr,
                            size_t offset, size_t size) {
    return proc_userns_write_map(handle, addr, offset, size, true);
}

size_t proc_psetgroups_stat(proc_handle_t *handle) {
    task_t *task = procfs_handle_task_or_current(handle);
    task_user_namespace_t *user_ns = task_user_namespace_of_task(task);
    size_t len = strlen("allow\n");

    if (!user_ns)
        return 0;
    mutex_lock(&user_ns->lock);
    len = user_ns->setgroups_state == TASK_USERNS_SETGROUPS_DENY
              ? strlen("deny\n")
              : strlen("allow\n");
    mutex_unlock(&user_ns->lock);
    return len;
}

size_t proc_psetgroups_read(proc_handle_t *handle, void *addr, size_t offset,
                            size_t size) {
    task_t *task = procfs_handle_task_or_current(handle);
    task_user_namespace_t *user_ns = task_user_namespace_of_task(task);
    const char *content = "allow\n";
    size_t content_len;

    if (!user_ns)
        return 0;
    mutex_lock(&user_ns->lock);
    content = user_ns->setgroups_state == TASK_USERNS_SETGROUPS_DENY
                  ? "deny\n"
                  : "allow\n";
    mutex_unlock(&user_ns->lock);

    content_len = strlen(content);
    if (offset >= content_len)
        return 0;

    size_t to_copy = MIN(size, content_len - offset);
    memcpy(addr, content + offset, to_copy);
    return to_copy;
}

ssize_t proc_psetgroups_write(proc_handle_t *handle, const void *addr,
                              size_t offset, size_t size) {
    return proc_userns_write_setgroups(handle, addr, offset, size);
}
