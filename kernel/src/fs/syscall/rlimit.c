#include <fs/fs_syscall.h>

uint64_t sys_get_rlimit(uint64_t resource, struct rlimit *lim) {
    if (resource >=
        sizeof(current_task->rlim) / sizeof(current_task->rlim[0])) {
        return (uint64_t)-EINVAL;
    }
    if (!lim || check_user_overflow((uint64_t)lim, sizeof(struct rlimit))) {
        return (uint64_t)-EFAULT;
    }

    struct rlimit value = current_task->rlim[resource];
    if (copy_to_user(lim, &value, sizeof(value))) {
        return (uint64_t)-EFAULT;
    }

    return 0;
}

uint64_t sys_prlimit64(uint64_t pid, int resource,
                       const struct rlimit *new_rlim, struct rlimit *old_rlim) {
    (void)pid;

    if (resource < 0 ||
        (uint64_t)resource >=
            sizeof(current_task->rlim) / sizeof(current_task->rlim[0])) {
        return (uint64_t)-EINVAL;
    }

    if (new_rlim &&
        check_user_overflow((uint64_t)new_rlim, sizeof(struct rlimit))) {
        return (uint64_t)-EFAULT;
    }
    if (old_rlim) {
        uint64_t ret = sys_get_rlimit(resource, old_rlim);
        if (ret != 0)
            return ret;
    }

    if (new_rlim) {
        struct rlimit value;
        if (copy_from_user(&value, new_rlim, sizeof(value))) {
            return (uint64_t)-EFAULT;
        }
        current_task->rlim[resource] = value;
    }

    return 0;
}
