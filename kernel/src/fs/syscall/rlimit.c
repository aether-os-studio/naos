#include <fs/fs_syscall.h>

uint64_t sys_get_rlimit(uint64_t resource, struct rlimit *lim)
{
    if (!lim || check_user_overflow((uint64_t)lim, sizeof(struct rlimit)))
    {
        return (uint64_t)-EFAULT;
    }
    *lim = current_task->rlim[resource];
    return 0;
}

uint64_t sys_prlimit64(uint64_t pid, int resource, const struct rlimit *new_rlim, struct rlimit *old_rlim)
{
    if (new_rlim && check_user_overflow((uint64_t)new_rlim, sizeof(struct rlimit)))
    {
        return (uint64_t)-EFAULT;
    }
    if (old_rlim)
    {
        uint64_t ret = sys_get_rlimit(resource, old_rlim);
        if (ret != 0)
            return ret;
    }

    if (new_rlim)
    {
        current_task->rlim[resource] = *new_rlim;
    }

    return 0;
}
