#include <task/seccomp.h>

#include <bpf/socket_filter.h>
#include <task/signal.h>
#include <task/task.h>
#include <task/task_syscall.h>

#if defined(__x86_64__)
#include <arch/x64/syscall/nr.h>
#elif defined(__aarch64__)
#include <arch/aarch64/syscall/nr.h>
#elif defined(__riscv__) || defined(__riscv)
#include <arch/riscv64/syscall/nr.h>
#endif

struct seccomp_filter {
    seccomp_filter_t *prev;
    uint32_t ref_count;
    uint16_t prog_len;
    uint16_t install_flags;
    struct sock_filter prog[];
};

static spinlock_t seccomp_ref_lock = SPIN_INIT;

#define SECCOMP_SIGSYS_CODE 1
#define SECCOMP_MAX_INSNS 4096

static inline void seccomp_filter_get(seccomp_filter_t *filter) {
    if (!filter)
        return;

    spin_lock(&seccomp_ref_lock);
    filter->ref_count++;
    spin_unlock(&seccomp_ref_lock);
}

static void seccomp_filter_put(seccomp_filter_t *filter) {
    while (filter) {
        seccomp_filter_t *prev = NULL;

        spin_lock(&seccomp_ref_lock);
        if (filter->ref_count > 1) {
            filter->ref_count--;
            spin_unlock(&seccomp_ref_lock);
            return;
        }
        prev = filter->prev;
        filter->prev = NULL;
        spin_unlock(&seccomp_ref_lock);

        free(filter);
        filter = prev;
    }
}

static uint32_t seccomp_audit_arch(void) {
#if defined(__x86_64__)
    return 0xc000003eU;
#elif defined(__aarch64__)
    return 0xc00000b7U;
#elif defined(__riscv__) || defined(__riscv)
    return 0xc00000f3U;
#else
    return 0;
#endif
}

static bool seccomp_strict_syscall_allowed(uint64_t syscall_nr) {
    switch (syscall_nr) {
    case SYS_READ:
    case SYS_WRITE:
    case SYS_EXIT:
    case SYS_RT_SIGRETURN:
        return true;
    default:
        return false;
    }
}

static int seccomp_validate_filter_prog(const struct sock_filter *prog,
                                        uint16_t len) {
    if (!prog || len == 0 || len > SECCOMP_MAX_INSNS)
        return -EINVAL;
    if (bpf_validate(prog, len) != 0)
        return -EINVAL;

    for (uint16_t i = 0; i < len; i++) {
        const struct sock_filter *insn = &prog[i];
        if (BPF_CLASS(insn->code) != BPF_LD || BPF_MODE(insn->code) != BPF_ABS)
            continue;

        size_t access_size = 0;
        switch (BPF_SIZE(insn->code)) {
        case BPF_W:
            access_size = sizeof(uint32_t);
            break;
        case BPF_H:
            access_size = sizeof(uint16_t);
            break;
        case BPF_B:
            access_size = sizeof(uint8_t);
            break;
        default:
            return -EINVAL;
        }

        if (insn->k > sizeof(struct seccomp_data) ||
            access_size > sizeof(struct seccomp_data) - insn->k) {
            return -EINVAL;
        }

        if ((access_size == sizeof(uint32_t) && (insn->k & 3)) ||
            (access_size == sizeof(uint16_t) && (insn->k & 1))) {
            return -EINVAL;
        }
    }

    return 0;
}

static int seccomp_install_filter(const struct sock_fprog *user_fprog,
                                  uint64_t flags) {
    if (!user_fprog)
        return -EFAULT;
    if (flags & ~(SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_SPEC_ALLOW)) {
        return -EINVAL;
    }
    if (!current_task->no_new_privs)
        return -EACCES;

    struct sock_fprog fprog;
    if (copy_from_user(&fprog, user_fprog, sizeof(fprog)))
        return -EFAULT;

    if (!fprog.filter || fprog.len == 0)
        return -EINVAL;
    if (check_user_overflow((uint64_t)fprog.filter,
                            (size_t)fprog.len * sizeof(struct sock_filter)) ||
        check_unmapped((uint64_t)fprog.filter,
                       (size_t)fprog.len * sizeof(struct sock_filter))) {
        return -EFAULT;
    }

    size_t prog_bytes = (size_t)fprog.len * sizeof(struct sock_filter);
    seccomp_filter_t *filter = calloc(1, sizeof(*filter) + prog_bytes);
    if (!filter)
        return -ENOMEM;

    if (copy_from_user(filter->prog, fprog.filter, prog_bytes)) {
        free(filter);
        return -EFAULT;
    }

    int ret = seccomp_validate_filter_prog(filter->prog, fprog.len);
    if (ret < 0) {
        free(filter);
        return ret;
    }

    filter->ref_count = 1;
    filter->prog_len = fprog.len;
    filter->install_flags = (uint16_t)flags;
    filter->prev = current_task->seccomp_filter;
    seccomp_filter_get(filter->prev);

    current_task->seccomp_filter = filter;
    current_task->seccomp_mode = SECCOMP_MODE_FILTER;
    return 0;
}

static uint32_t seccomp_run_filters(task_t *task, uint64_t syscall_nr,
                                    uint64_t instruction_pointer,
                                    const uint64_t args[6]) {
    if (!task || !task->seccomp_filter)
        return SECCOMP_RET_ALLOW;

    struct seccomp_data data;
    memset(&data, 0, sizeof(data));
    data.nr = (int)syscall_nr;
    data.arch = seccomp_audit_arch();
    data.instruction_pointer = instruction_pointer;
    memcpy(data.args, args, sizeof(data.args));

    uint32_t result = SECCOMP_RET_ALLOW;
    for (seccomp_filter_t *filter = task->seccomp_filter; filter;
         filter = filter->prev) {
        uint32_t candidate = bpf_run(filter->prog, filter->prog_len,
                                     (const uint8_t *)&data, sizeof(data));
        if ((int32_t)candidate < (int32_t)result)
            result = candidate;
    }

    return result;
}

static void seccomp_trap_sigsys(task_t *task, uint64_t syscall_nr,
                                uint64_t instruction_pointer,
                                uint32_t action_data) {
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGSYS;
    info.si_errno = (int)(action_data & SECCOMP_RET_DATA);
    info.si_code = SECCOMP_SIGSYS_CODE;
    info._sifields._sigsys._call_addr = (void *)instruction_pointer;
    info._sifields._sigsys._syscall = (int)syscall_nr;
    info._sifields._sigsys._arch = seccomp_audit_arch();
    task_commit_signal(task, SIGSYS, &info);
}

static bool seccomp_apply_strict(uint64_t syscall_nr) {
    if (seccomp_strict_syscall_allowed(syscall_nr))
        return false;

    task_exit(128 + SIGKILL);
    return true;
}

static bool seccomp_apply_filter(task_t *task, uint64_t syscall_nr,
                                 uint64_t instruction_pointer,
                                 const uint64_t args[6], uint64_t *result_out) {
    uint32_t action =
        seccomp_run_filters(task, syscall_nr, instruction_pointer, args);
    uint32_t action_full = action & SECCOMP_RET_ACTION_FULL;

    switch (action_full) {
    case SECCOMP_RET_ALLOW:
    case SECCOMP_RET_LOG:
        return false;

    case SECCOMP_RET_ERRNO:
        *result_out = (uint64_t)-(int32_t)(action & SECCOMP_RET_DATA);
        return true;

    case SECCOMP_RET_TRAP:
        seccomp_trap_sigsys(task, syscall_nr, instruction_pointer, action);
        *result_out = (uint64_t)-ENOSYS;
        return true;

    case SECCOMP_RET_KILL_THREAD:
        task_exit_thread(128 + SIGSYS);
        return true;

    case SECCOMP_RET_KILL_PROCESS:
    default:
        task_exit(128 + SIGSYS);
        return true;
    }
}

bool task_seccomp_apply(struct pt_regs *regs, uint64_t syscall_nr,
                        uint64_t instruction_pointer, const uint64_t args[6],
                        uint64_t *result_out) {
    (void)regs;

    task_t *task = current_task;
    if (!task || !result_out)
        return false;

    switch (task->seccomp_mode) {
    case SECCOMP_MODE_DISABLED:
        return false;
    case SECCOMP_MODE_STRICT:
        return seccomp_apply_strict(syscall_nr);
    case SECCOMP_MODE_FILTER:
        return seccomp_apply_filter(task, syscall_nr, instruction_pointer, args,
                                    result_out);
    default:
        return false;
    }
}

int task_seccomp_inherit(task_t *child, task_t *parent) {
    if (!child || !parent)
        return -EINVAL;

    child->no_new_privs = parent->no_new_privs;
    child->seccomp_mode = parent->seccomp_mode;
    child->seccomp_filter = parent->seccomp_filter;
    seccomp_filter_get(child->seccomp_filter);
    return 0;
}

void task_seccomp_release(task_t *task) {
    if (!task || !task->seccomp_filter)
        return;

    seccomp_filter_put(task->seccomp_filter);
    task->seccomp_filter = NULL;
}

uint64_t sys_seccomp(uint64_t operation, uint64_t flags, void *uargs) {
    switch (operation) {
    case SECCOMP_SET_MODE_STRICT:
        if (flags != 0 || uargs != NULL)
            return (uint64_t)-EINVAL;
        if (current_task->seccomp_mode != SECCOMP_MODE_DISABLED)
            return (uint64_t)-EINVAL;
        current_task->seccomp_mode = SECCOMP_MODE_STRICT;
        return 0;

    case SECCOMP_SET_MODE_FILTER:
        if (current_task->seccomp_mode == SECCOMP_MODE_STRICT)
            return (uint64_t)-EINVAL;
        return (uint64_t)seccomp_install_filter(
            (const struct sock_fprog *)uargs, flags);

    case SECCOMP_GET_ACTION_AVAIL: {
        if (flags != 0 || !uargs)
            return (uint64_t)-EINVAL;

        uint32_t action = 0;
        if (copy_from_user(&action, uargs, sizeof(action)))
            return (uint64_t)-EFAULT;

        switch (action) {
        case SECCOMP_RET_KILL_THREAD:
        case SECCOMP_RET_KILL_PROCESS:
        case SECCOMP_RET_TRAP:
        case SECCOMP_RET_ERRNO:
        case SECCOMP_RET_ALLOW:
            return 0;
        default:
            return (uint64_t)-EOPNOTSUPP;
        }
    }

    case SECCOMP_GET_NOTIF_SIZES: {
        if (flags != 0 || !uargs)
            return (uint64_t)-EINVAL;

        struct seccomp_notif_sizes sizes = {
            .seccomp_notif = sizeof(struct seccomp_notif),
            .seccomp_notif_resp = sizeof(struct seccomp_notif_resp),
            .seccomp_data = sizeof(struct seccomp_data),
        };
        if (copy_to_user(uargs, &sizes, sizeof(sizes)))
            return (uint64_t)-EFAULT;
        return 0;
    }

    default:
        return (uint64_t)-EINVAL;
    }
}
