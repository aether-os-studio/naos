#include <fs/fs_syscall.h>
#include <task/task.h>

static task_t *rlimit_target_task(uint64_t pid, int resource, bool write) {
    task_t *target;
    uint64_t self_tgid;

    if (!current_task) {
        return NULL;
    }

    if (pid == 0 || pid == current_task->pid ||
        pid == task_effective_tgid(current_task)) {
        return current_task;
    }

    target = task_find_by_pid(pid);
    if (!target) {
        return NULL;
    }

    self_tgid = task_effective_tgid(current_task);
    if (task_effective_tgid(target) != self_tgid) {
        printk(
            "sys_prlimit64: unsupported cross-process %s pid=%lu resource=%d "
            "current_pid=%lu\n",
            write ? "write" : "read", pid, resource, current_task->pid);
        return ERR_PTR(-ENOSYS);
    }

    return target;
}

uint64_t sys_set_rlimit(uint64_t resource, const struct rlimit *lim) {
    return sys_prlimit64(0, (int)resource, lim, NULL);
}

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
    task_t *target;

    if (resource < 0 ||
        (uint64_t)resource >=
            sizeof(current_task->rlim) / sizeof(current_task->rlim[0])) {
        return (uint64_t)-EINVAL;
    }

    if (new_rlim &&
        check_user_overflow((uint64_t)new_rlim, sizeof(struct rlimit))) {
        return (uint64_t)-EFAULT;
    }

    target = rlimit_target_task(pid, resource, new_rlim != NULL);
    if (!target) {
        return (uint64_t)-ESRCH;
    }
    if (IS_ERR(target)) {
        return (uint64_t)PTR_ERR(target);
    }

    if (old_rlim) {
        struct rlimit value = target->rlim[resource];
        if (!old_rlim ||
            check_user_overflow((uint64_t)old_rlim, sizeof(struct rlimit))) {
            return (uint64_t)-EFAULT;
        }
        if (copy_to_user(old_rlim, &value, sizeof(value))) {
            return (uint64_t)-EFAULT;
        }
    }

    if (new_rlim) {
        struct rlimit value;
        if (copy_from_user(&value, new_rlim, sizeof(value))) {
            return (uint64_t)-EFAULT;
        }
        target->rlim[resource] = value;
    }

    return 0;
}
