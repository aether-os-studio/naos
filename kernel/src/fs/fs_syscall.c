#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/pipe.h>
#include <net/net_syscall.h>
#include <drivers/kernel_logger.h>

char *at_resolve_pathname(int dirfd, char *pathname)
{
    if (pathname[0] == '/')
    { // by absolute pathname
        return strdup(pathname);
    }
    else if (pathname[0] != '/')
    {
        if (dirfd == (int)AT_FDCWD)
        { // relative to cwd
            return strdup(pathname);
        }
        else
        { // relative to dirfd, resolve accordingly
            if (dirfd < 0 || dirfd > MAX_FD_NUM || !current_task->fd_info->fds[dirfd] || !current_task->fd_info->fds[dirfd]->node)
                return NULL;

            vfs_node_t node = current_task->fd_info->fds[dirfd]->node;

            char *dirname = vfs_get_fullpath(node);

            int rootDirLen = strlen(dirname);
            int pathnameLen = 0;
            if (pathname)
                pathnameLen = strlen(pathname) + 1;

            char *out = malloc(rootDirLen + 1 + pathnameLen);
            memcpy(out, dirname, rootDirLen);
            out[rootDirLen] = '/';
            if (pathname)
                memcpy(out + rootDirLen + 1, pathname, pathnameLen);
            else
                out[rootDirLen + 1] = 0;

            free(dirname);

            return out;
        }
    }

    return NULL;
}

char *at_resolve_pathname_fullpath(int dirfd, char *pathname)
{
    if (pathname[0] == '/')
    { // by absolute pathname
        return strdup(pathname);
    }
    else if (pathname[0] != '/')
    {
        if (dirfd == AT_FDCWD)
        { // relative to cwd
            char *cwd = current_task->cwd ? vfs_get_fullpath(current_task->cwd) : strdup("/");
            int cwd_len = strlen(cwd);
            char *ret = malloc(cwd_len + 1 + strlen(pathname));
            sprintf(ret, "%s/%s", cwd, pathname);
            free(cwd);
            return ret;
        }
        else
        { // relative to dirfd, resolve accordingly
            if (dirfd < 0 || dirfd > MAX_FD_NUM || !current_task->fd_info->fds[dirfd] || !current_task->fd_info->fds[dirfd]->node)
                return NULL;

            vfs_node_t node = current_task->fd_info->fds[dirfd]->node;

            char *dirname = vfs_get_fullpath(node);

            int rootDirLen = strlen(dirname);
            int pathnameLen = strlen(pathname) + 1;

            char *out = malloc(rootDirLen + 1 + pathnameLen);
            memcpy(out, dirname, rootDirLen);
            out[rootDirLen] = '/';
            memcpy(out + rootDirLen + 1, pathname, pathnameLen);

            free(dirname);

            return out;
        }
    }

    return NULL;
}

extern void epoll_init();
extern void eventfd_init();
extern void signalfd_init();
extern void timerfd_init();
extern void memfd_init();

void fs_syscall_init()
{
    epoll_init();
    eventfd_init();
    signalfd_init();
    timerfd_init();
    memfd_init();
}
