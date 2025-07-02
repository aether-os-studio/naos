#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <net/net_syscall.h>

char *at_resolve_pathname(int dirfd, char *pathname)
{
    if (pathname[0] == '/')
    { // by absolute pathname
        return strdup(pathname);
    }
    else if (pathname[0] != '/')
    {
        if (dirfd == AT_FDCWD)
        { // relative to cwd
            return strdup(pathname);
        }
        else
        { // relative to dirfd, resolve accordingly
            vfs_node_t node = current_task->fds[dirfd]->node;
            if (!node)
                return NULL;
            if (node->type != file_dir)
                return NULL;

            char *dirname = vfs_get_fullpath(node);

            char *prefix = vfs_get_fullpath(node->root);

            int prefixLen = strlen(prefix);
            int rootDirLen = strlen(dirname);
            int pathnameLen = strlen(pathname) + 1;

            char *out = malloc(prefixLen + rootDirLen + 1 + pathnameLen + 1);

            memcpy(out, prefix, prefixLen);
            memcpy(&out[prefixLen], dirname, rootDirLen);
            out[prefixLen + rootDirLen] = '/';
            memcpy(&out[prefixLen + rootDirLen + 1], pathname, pathnameLen);

            free(dirname);
            free(prefix);

            return out;
        }
    }

    return NULL;
}

extern void epoll_init();
extern void eventfd_init();
extern void signalfd_init();
extern void timerfd_init();

void fs_syscall_init()
{
    epoll_init();
    eventfd_init();
    signalfd_init();
    timerfd_init();
}

void wake_blocked_tasks(task_block_list_t *head)
{
    task_block_list_t *current = head->next;
    head->next = NULL;

    while (current)
    {
        task_block_list_t *next = current->next;
        if (current->task)
        {
            task_unblock(current->task, EOK);
        }
        free(current);
        current = next;
    }
}
