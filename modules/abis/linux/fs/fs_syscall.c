#include <fs/fs_syscall.h>
#include <task/task.h>

static char *join_pathname(const char *base, const char *pathname) {
    if (!base)
        return NULL;

    size_t base_len = strlen(base);
    size_t path_len = pathname ? strlen(pathname) : 0;
    bool need_sep = path_len && base_len && strcmp(base, "/");
    size_t need = base_len + (need_sep ? 1 : 0) + path_len + 1;

    char *out = malloc(need);
    if (!out)
        return NULL;

    size_t cursor = 0;
    if (base_len) {
        memcpy(out, base, base_len);
        cursor = base_len;
    }
    if (need_sep)
        out[cursor++] = '/';
    if (path_len) {
        memcpy(out + cursor, pathname, path_len);
        cursor += path_len;
    }
    out[cursor] = '\0';

    return out;
}

char *at_resolve_pathname(int dirfd, char *pathname) {
    if (pathname[0] == '/') { // by absolute pathname
        return strdup(pathname);
    } else if (pathname[0] != '/') {
        if (dirfd == (int)AT_FDCWD) { // relative to cwd
            char *cwd = current_task->cwd ? vfs_get_fullpath(current_task->cwd)
                                          : strdup("/");
            if (!cwd)
                return NULL;

            char *ret = join_pathname(cwd, pathname);
            free(cwd);
            return ret;
        } else { // relative to dirfd, resolve accordingly
            if (dirfd < 0 || dirfd >= MAX_FD_NUM ||
                !current_task->fd_info->fds[dirfd] ||
                !current_task->fd_info->fds[dirfd]->node)
                return NULL;

            vfs_node_t node = current_task->fd_info->fds[dirfd]->node;

            char *dirname = vfs_get_fullpath(node);
            char *out = join_pathname(dirname, pathname);
            free(dirname);

            return out;
        }
    }

    return NULL;
}

char *at_resolve_pathname_fullpath(int dirfd, char *pathname) {
    return at_resolve_pathname(dirfd, pathname);
}

extern void epoll_init();
extern void eventfd_init();
extern void signalfd_init();
extern void timerfd_init();
extern void memfd_init();
extern void pidfd_init();

void fs_syscall_init() {
    epoll_init();
    eventfd_init();
    signalfd_init();
    timerfd_init();
    memfd_init();
    pidfd_init();
}
