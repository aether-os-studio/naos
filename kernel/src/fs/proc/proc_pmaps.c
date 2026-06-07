#include <fs/proc/proc.h>
#include <task/task.h>

static size_t proc_maps_format_prefix(const vma_t *vma, char *buf,
                                      size_t size) {
    vfs_node_t *vfs_node = vma ? vma->node : NULL;
    char perms[5];
    int written;

    if (!vma || !buf || size == 0)
        return 0;

    perms[0] = (vma->vm_flags & VMA_READ) ? 'r' : '-';
    perms[1] = (vma->vm_flags & VMA_WRITE) ? 'w' : '-';
    perms[2] = (vma->vm_flags & VMA_EXEC) ? 'x' : '-';
    perms[3] = (vma->vm_flags & VMA_SHARED) ? 's' : 'p';
    perms[4] = '\0';

    written = snprintf(buf, size, "%012lx-%012lx %s %08lx %02x:%02x %lu",
                       vma->vm_start, vma->vm_end, perms, vma->vm_offset,
                       vfs_node ? (vfs_node->i_rdev >> 8) & 0xFF : 0,
                       vfs_node ? vfs_node->i_rdev & 0xFF : 0,
                       vfs_node ? vfs_node->inode : 0);
    if (written < 0)
        return 0;

    return MIN((size_t)written, size - 1);
}

static size_t proc_maps_vma_line_len(const vma_t *vma) {
    char prefix[128];
    size_t len = proc_maps_format_prefix(vma, prefix, sizeof(prefix));
    const char *pathname = vma ? vma->vm_name : NULL;

    if (pathname && pathname[0])
        len += 15 + strlen(pathname);
    return len + 1;
}

static size_t proc_maps_copy_piece(char *addr, size_t size, size_t offset,
                                   size_t *position, const char *data,
                                   size_t data_len, size_t copied) {
    if (!position || !data || data_len == 0)
        return copied;

    if (copied < size && *position + data_len > offset) {
        size_t piece_offset = offset > *position ? offset - *position : 0;
        size_t available = data_len - piece_offset;
        size_t to_copy = MIN(size - copied, available);

        memcpy(addr + copied, data + piece_offset, to_copy);
        copied += to_copy;
    }

    *position += data_len;
    return copied;
}

static size_t proc_maps_copy_vma_line(const vma_t *vma, char *addr,
                                      size_t offset, size_t size,
                                      size_t *position, size_t copied) {
    static const char pathname_padding[] = "               ";
    char prefix[128];
    size_t prefix_len = proc_maps_format_prefix(vma, prefix, sizeof(prefix));
    const char *pathname = vma ? vma->vm_name : NULL;

    copied = proc_maps_copy_piece(addr, size, offset, position, prefix,
                                  prefix_len, copied);
    if (pathname && pathname[0]) {
        copied = proc_maps_copy_piece(addr, size, offset, position,
                                      pathname_padding, 15, copied);
        copied = proc_maps_copy_piece(addr, size, offset, position, pathname,
                                      strlen(pathname), copied);
    }
    copied =
        proc_maps_copy_piece(addr, size, offset, position, "\n", 1, copied);
    return copied;
}

static size_t proc_maps_total_len_locked(vma_manager_t *mgr) {
    size_t total = 0;
    rb_node_t *node;

    if (!mgr)
        return 0;

    node = rb_first(&mgr->vma_tree);
    while (node) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);
        total += proc_maps_vma_line_len(vma);
        node = rb_next(node);
    }

    return total;
}

size_t proc_pmaps_stat(proc_handle_t *handle) {
    task_t *task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;

    if (!task || !task->mm)
        return 0;

    vma_manager_t *mgr = &task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    content_len = proc_maps_total_len_locked(mgr);
    spin_unlock(&mgr->lock);
    return content_len;
}

size_t proc_pmaps_read(proc_handle_t *handle, void *addr, size_t offset,
                       size_t size) {
    task_t *task = procfs_handle_task_or_current(handle);
    char buffer[4096];
    size_t position = 0;
    size_t copied = 0;
    size_t window;

    if (!task || !task->mm || !addr || size == 0)
        return 0;

    window = MIN(size, sizeof(buffer));

    vma_manager_t *mgr = &task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    rb_node_t *node = rb_first(&mgr->vma_tree);
    while (node && copied < window) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);
        size_t line_len = proc_maps_vma_line_len(vma);

        if (position + line_len > offset)
            copied = proc_maps_copy_vma_line(vma, buffer, offset, window,
                                             &position, copied);
        else
            position += line_len;

        node = rb_next(node);
    }
    spin_unlock(&mgr->lock);

    if (copied > 0)
        memcpy(addr, buffer, copied);
    return copied;
}
