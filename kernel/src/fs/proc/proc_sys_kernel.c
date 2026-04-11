#include <fs/proc.h>
#include <task/ns.h>
#include <task/task.h>

static const char *proc_sys_kernel_uts_value(size_t *len_out, bool domainname) {
    task_t *task = current_task;
    task_uts_namespace_t *uts_ns =
        (task && task->nsproxy) ? task->nsproxy->uts_ns : NULL;
    const char *value;

    if (domainname) {
        value = uts_ns ? uts_ns->domainname : "";
    } else {
        value = uts_ns ? uts_ns->nodename : "aether";
    }

    if (len_out)
        *len_out = strlen(value);
    return value;
}

static size_t proc_sys_kernel_uts_read(void *addr, size_t offset, size_t size,
                                       bool domainname) {
    size_t len = 0;
    const char *content = proc_sys_kernel_uts_value(&len, domainname);

    if (offset >= len)
        return 0;

    size_t to_copy = MIN(size, len - offset);
    memcpy(addr, content + offset, to_copy);
    return to_copy;
}

static ssize_t proc_sys_kernel_uts_write(const void *addr, size_t offset,
                                         size_t size, bool domainname) {
    task_t *task = current_task;
    task_uts_namespace_t *uts_ns =
        (task && task->nsproxy) ? task->nsproxy->uts_ns : NULL;
    char *target;
    size_t max_len;
    size_t copy_len;

    (void)offset;
    if (!uts_ns || !addr)
        return -EINVAL;

    target = domainname ? uts_ns->domainname : uts_ns->nodename;
    max_len = sizeof(uts_ns->domainname) - 1;
    copy_len = MIN(size, max_len);

    while (copy_len > 0 && (((const char *)addr)[copy_len - 1] == '\n' ||
                            ((const char *)addr)[copy_len - 1] == '\0')) {
        copy_len--;
    }

    memcpy(target, addr, copy_len);
    target[copy_len] = '\0';
    return size;
}

size_t proc_sys_kernel_osrelease_stat(proc_handle_t *handle) {
    return strlen(BUILD_VERSION);
}

size_t proc_sys_kernel_osrelease_read(proc_handle_t *handle, void *addr,
                                      size_t offset, size_t size) {
    const char *content = BUILD_VERSION;
    size_t len = strlen(content);
    if (offset >= len) {
        return 0;
    }
    size_t to_copy = MIN(size, len - offset);
    memcpy(addr, content + offset, to_copy);
    return to_copy;
}

size_t proc_sys_kernel_hostname_stat(proc_handle_t *handle) {
    size_t len = 0;

    (void)handle;
    (void)proc_sys_kernel_uts_value(&len, false);
    return len;
}

size_t proc_sys_kernel_hostname_read(proc_handle_t *handle, void *addr,
                                     size_t offset, size_t size) {
    (void)handle;
    return proc_sys_kernel_uts_read(addr, offset, size, false);
}

ssize_t proc_sys_kernel_hostname_write(proc_handle_t *handle, const void *addr,
                                       size_t offset, size_t size) {
    (void)handle;
    return proc_sys_kernel_uts_write(addr, offset, size, false);
}

size_t proc_sys_kernel_domainname_stat(proc_handle_t *handle) {
    size_t len = 0;

    (void)handle;
    (void)proc_sys_kernel_uts_value(&len, true);
    return len;
}

size_t proc_sys_kernel_domainname_read(proc_handle_t *handle, void *addr,
                                       size_t offset, size_t size) {
    (void)handle;
    return proc_sys_kernel_uts_read(addr, offset, size, true);
}

ssize_t proc_sys_kernel_domainname_write(proc_handle_t *handle,
                                         const void *addr, size_t offset,
                                         size_t size) {
    (void)handle;
    return proc_sys_kernel_uts_write(addr, offset, size, true);
}
