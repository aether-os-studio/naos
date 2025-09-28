#include <fs/vfs/proc.h>
#include <arch/arch.h>
#include <task/task.h>

__attribute__((used, section(".limine_requests"))) static volatile struct
    limine_executable_cmdline_request executable_cmdline_request = {
        .id = LIMINE_EXECUTABLE_CMDLINE_REQUEST,
};

spinlock_t procfs_oplock = {0};

vfs_node_t cmdline = NULL;

const char filesystems_content[] = "nodev\tsysfs\n"
                                   "nodev\ttmpfs\n"
                                   "nodev\tproc\n"
                                   "     \text4\n"
                                   "     \text3\n"
                                   "     \text2\n";

const char *get_vma_permissions(vma_t *vma) {
    static char perms[5];

    perms[0] = (vma->vm_flags & VMA_READ) ? 'r' : '-';
    perms[1] = (vma->vm_flags & VMA_WRITE) ? 'w' : '-';
    perms[2] = (vma->vm_flags & VMA_EXEC) ? 'x' : '-';
    perms[3] = (vma->vm_flags & VMA_SHARED) ? 's' : 'p';
    perms[4] = '\0';

    return perms;
}

char *proc_gen_maps_file(task_t *task, size_t *content_len) {
    vma_t *vma = task->arch_context->mm->task_vma_mgr.vma_list;

    size_t offset = 0;
    size_t ctn_len = DEFAULT_PAGE_SIZE;
    char *buf = malloc(ctn_len);

    while (vma) {
        vfs_node_t node = NULL;
        if (vma->vm_fd != -1) {
            node = current_task->fd_info->fds[vma->vm_fd]->node;
        }

        int len = sprintf(
            buf + offset, "%012lx-%012lx %s %08lx %02x:%02x %lu", vma->vm_start,
            vma->vm_end, get_vma_permissions(vma),
            (unsigned long)vma->vm_offset, node ? ((node->dev >> 8) & 0xFF) : 0,
            node ? (node->dev & 0xFF) : 0, node ? node->inode : 0);

        if (offset + len > ctn_len) {
            ctn_len = (offset + len + DEFAULT_PAGE_SIZE - 1) &
                      ~(DEFAULT_PAGE_SIZE - 1);
            buf = realloc(buf, ctn_len);
        }
        offset += len;

        const char *pathname = vma->vm_name;
        if (pathname && strlen(pathname) > 0) {
            len = sprintf(buf + offset, "%*s%s", 15, "", pathname);
            if (offset + len > ctn_len) {
                ctn_len = (offset + len + DEFAULT_PAGE_SIZE - 1) &
                          ~(DEFAULT_PAGE_SIZE - 1);
                buf = realloc(buf, ctn_len);
            }
            offset += len;
        }

        len = sprintf(buf + offset, "\n");
        if (offset + len > ctn_len) {
            ctn_len = (offset + len + DEFAULT_PAGE_SIZE - 1) &
                      ~(DEFAULT_PAGE_SIZE - 1);
            buf = realloc(buf, ctn_len);
        }
        offset += len;

        vma = vma->vm_next;
    }

    *content_len = offset;

    return buf;
}

char *proc_gen_stat_file(task_t *task, size_t *content_len) {
    char *buffer = malloc(DEFAULT_PAGE_SIZE);
    int len = sprintf(
        buffer,
        "%d (%s) %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld "
        "%ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu "
        "%lu %d %d %u %u %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %d\n",
        task->pid,                         // pid
        task->name,                        // name
        'R',                               // state
        task->ppid,                        // ppid
        0,                                 // pgrp
        0,                                 // session
        0,                                 // tty_nr
        0,                                 // tpgid
        0,                                 // flags
        0,                                 // minflt
        0,                                 // cminflt
        0,                                 // majflt
        0,                                 // cmajflt
        0,                                 // utime
        0,                                 // stime
        0,                                 // cutime
        0,                                 // cstime
        0,                                 // priority
        0,                                 // nice
        1,                                 // num_threads
        0,                                 // itrealvalue
        0,                                 // starttime
        0,                                 // vsize
        0,                                 // rss
        0,                                 // rsslim
        task->load_start,                  // startcode
        task->load_end,                    // endcode
        USER_STACK_START,                  // startstack
        0,                                 // kstkesp
        0,                                 // ksteip
        task->signal,                      // signal
        task->blocked,                     // blocked
        0,                                 // sigignore
        0,                                 // sigcatch
        0,                                 // wchan
        0,                                 // nswap
        0,                                 // cnswap
        0,                                 // exit_signal
        task->cpu_id,                      // processor
        0,                                 // rt_priority
        0,                                 // policy
        0,                                 // delayacct_blkio_ticks
        0,                                 // guest_time
        0,                                 // cguest_time
        0,                                 // start_data
        0,                                 // end_data
        task->arch_context->mm->brk_start, // start_brk
        0,                                 // arg_start
        0,                                 // arg_end
        0,                                 // env_start
        0,                                 // env_end
        task->state                        // exit_code
    );

    *content_len = len;

    return buffer;
}

ssize_t procfs_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    void *file = fd->node->handle;
    proc_handle_t *handle = (proc_handle_t *)file;
    if (!handle) {
        return -EINVAL;
    }
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }

    if (!strcmp(handle->name, "self/exe")) {
        if (task->exec_node) {
            char *fullpath = vfs_get_fullpath(task->exec_node);
            size_t content_len = strlen(fullpath);
            if (offset >= content_len) {
                free(fullpath);
                return 0;
            }
            content_len = MIN(content_len, offset + size);
            size_t to_copy = MIN(content_len, size);
            memcpy(addr, fullpath + offset, to_copy);
            free(fullpath);
            ((char *)addr)[to_copy] = '\0';
        } else
            return 0;
    } else if (!strcmp(handle->name, "self/maps")) {
        size_t content_len = 0;
        char *content = proc_gen_maps_file(task, &content_len);
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
    } else if (!strcmp(handle->name, "self/stat")) {
        size_t content_len = 0;
        char *content = proc_gen_stat_file(task, &content_len);
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
    } else if (!strcmp(handle->name, "cpuinfo")) {
        char *content = generate_cpuinfo_buffer_dynamic();
        size_t content_len = strlen(content);
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
    } else if (!strcmp(handle->name, "cmdline")) {
        ssize_t len = strlen(executable_cmdline_request.response->cmdline);
        if (len == 0)
            return 0;
        if (offset >= len) {
            return 0;
        }
        len = MIN(len, offset + size);
        size_t to_copy = MIN(len, size);
        memcpy(addr, executable_cmdline_request.response->cmdline, to_copy);
        return len;
    } else if (!strcmp(handle->name, "proc_cmdline")) {
        ssize_t len = strlen(task->cmdline);
        if (len == 0)
            return 0;
        if (offset >= len) {
            return 0;
        }
        len = MIN(len, offset + size);
        size_t to_copy = MIN(len, size);
        memcpy(addr, task->cmdline, to_copy);
        return len;
    }

    return 0;
}

ssize_t procfs_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    return size;
}

vfs_node_t procfs_root = NULL;
int procfs_id = 0;

static int dummy() { return 0; }

void procfs_open(void *parent, const char *name, vfs_node_t node) {}

bool procfs_close(void *current) { return false; }

ssize_t procfs_readlink(vfs_node_t node, void *addr, size_t offset,
                        size_t size) {
    proc_handle_t *handle = node->handle;
    if (!strcmp(handle->name, "self/exe") && current_task->exec_node) {
        char *fullpath = vfs_get_fullpath(current_task->exec_node);
        int len = strlen(fullpath);
        len = MIN(len, size);
        memcpy(addr, fullpath, len);
        return len;
    }

    return 0;
}

int procfs_mount(vfs_node_t dev, vfs_node_t node) {
    list_foreach(procfs_root->child, i) {
        vfs_node_t child = (vfs_node_t)i->data;
        list_delete(procfs_root->child, child);
        list_prepend(node->child, child);
        child->parent = node;
    }

    if (procfs_root == node)
        return -EALREADY;

    procfs_root = node;

    procfs_root->type = file_dir;
    procfs_root->mode = 0644;
    procfs_root->fsid = procfs_id;

    vfs_node_t procfs_cpuinfo = vfs_node_alloc(procfs_root, "cpuinfo");
    procfs_cpuinfo->type = file_none;
    procfs_cpuinfo->mode = 0644;
    proc_handle_t *procfs_cpuinfo_handle = malloc(sizeof(proc_handle_t));
    procfs_cpuinfo->handle = procfs_cpuinfo_handle;
    procfs_cpuinfo_handle->task = NULL;
    sprintf(procfs_cpuinfo_handle->name, "cpuinfo");

    vfs_node_t procfs_self = vfs_node_alloc(procfs_root, "self");
    procfs_self->type = file_dir;
    procfs_self->mode = 0644;

    // vfs_node_t self_exe = vfs_node_alloc(procfs_self, "exe");
    // self_exe->type = file_none;
    // self_exe->mode = 0700;
    // proc_handle_t *self_exe_handle = malloc(sizeof(proc_handle_t));
    // self_exe->handle = self_exe_handle;
    // self_exe_handle->task = NULL;
    // self_exe->linkto = rootdir;
    // sprintf(self_exe_handle->name, "self/exe");

    vfs_node_t self_environ = vfs_node_alloc(procfs_self, "environ");
    self_environ->type = file_none;
    self_environ->mode = 0700;
    proc_handle_t *self_environ_handle = malloc(sizeof(proc_handle_t));
    self_environ->handle = self_environ_handle;
    self_environ_handle->task = NULL;
    sprintf(self_environ_handle->name, "self/environ");

    vfs_node_t self_maps = vfs_node_alloc(procfs_self, "maps");
    self_maps->type = file_none;
    self_maps->mode = 0700;
    proc_handle_t *self_maps_handle = malloc(sizeof(proc_handle_t));
    self_maps->handle = self_maps_handle;
    self_maps_handle->task = NULL;
    sprintf(self_maps_handle->name, "self/maps");

    vfs_node_t self_stat = vfs_node_alloc(procfs_self, "stat");
    self_stat->type = file_none;
    self_stat->mode = 0700;
    proc_handle_t *self_stat_handle = malloc(sizeof(proc_handle_t));
    self_stat->handle = self_stat_handle;
    self_stat_handle->task = NULL;
    sprintf(self_stat_handle->name, "self/stat");

    cmdline = vfs_node_alloc(procfs_root, "cmdline");
    cmdline->type = file_none;
    cmdline->mode = 0700;
    proc_handle_t *handle = malloc(sizeof(proc_handle_t));
    cmdline->handle = handle;
    handle->task = NULL;
    sprintf(handle->name, "cmdline");

    return 0;
}

static struct vfs_callback callbacks = {
    .open = (vfs_open_t)procfs_open,
    .close = (vfs_close_t)dummy,
    .read = procfs_read,
    .write = (vfs_write_t)procfs_write,
    .readlink = (vfs_readlink_t)procfs_readlink,
    .mkdir = (vfs_mk_t)dummy,
    .mkfile = (vfs_mk_t)dummy,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .mknod = (vfs_mknod_t)dummy,
    .chmod = (vfs_chmod_t)dummy,
    .delete = (vfs_del_t)dummy,
    .rename = (vfs_rename_t)dummy,
    .stat = (vfs_stat_t)dummy,
    .ioctl = (vfs_ioctl_t)dummy,
    .map = (vfs_mapfile_t)dummy,
    .poll = (vfs_poll_t)dummy,
    .mount = (vfs_mount_t)procfs_mount,
    .unmount = (vfs_unmount_t)dummy,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,
};

fs_t procfs = {
    .name = "proc",
    .magic = 0x9fa0,
    .callback = &callbacks,
};

void proc_init() {
    procfs_id = vfs_regist(&procfs);

    procfs_root = vfs_node_alloc(NULL, "proc");
    procfs_root->fsid = procfs_id;
}

void procfs_on_new_task(task_t *task) {
    spin_lock(&procfs_oplock);

    char name[MAX_PID_NAME_LEN];
    sprintf(name, "%d", task->pid);

    vfs_node_t node = vfs_child_append(procfs_root, name, NULL);
    node->type = file_dir;
    node->mode = 0644;

    vfs_node_t cmdline = vfs_child_append(node, "cmdline", NULL);
    cmdline->type = file_none;
    cmdline->mode = 0700;
    proc_handle_t *handle = malloc(sizeof(proc_handle_t));
    cmdline->handle = handle;
    handle->task = task;
    sprintf(handle->name, "proc_cmdline");

    spin_unlock(&procfs_oplock);
}

void procfs_on_exit_task(task_t *task) {
    spin_lock(&procfs_oplock);

    char name[6 + MAX_PID_NAME_LEN];
    sprintf(name, "/proc/%d", task->pid);

    vfs_node_t node = vfs_open(name);
    if (node && node->parent) {
        list_delete(node->parent->child, node);
        if (node->handle)
            free(node->handle);
        vfs_free(node);
    }

    spin_unlock(&procfs_oplock);
}
