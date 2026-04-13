#include <task/ptrace.h>
#include <task/task_syscall.h>

#if defined(__x86_64__)
typedef struct x64_user_regs_struct {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t orig_rax;
    uint64_t rip;
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t ds;
    uint64_t es;
    uint64_t fs;
    uint64_t gs;
} x64_user_regs_struct_t;
#endif

#if defined(__aarch64__)
typedef struct aarch64_user_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} aarch64_user_pt_regs_t;
#endif

static task_t *ptrace_find_target(task_t *tracer, uint64_t pid) {
    task_t *target;

    if (!tracer || pid == 0)
        return NULL;

    target = task_find_by_pid(pid);
    if (!target || target->is_kernel || target == tracer)
        return NULL;

    return target;
}

static bool ptrace_task_access_ok(task_t *tracer, task_t *target) {
    if (!tracer || !target)
        return false;

    if (tracer->euid == 0)
        return true;

    return tracer->euid == target->euid && tracer->uid == target->uid;
}

static inline struct pt_regs *ptrace_task_regs(task_t *task) {
    if (!task || !task->syscall_stack)
        return NULL;

    return (struct pt_regs *)task->syscall_stack - 1;
}

static inline struct pt_regs *ptrace_task_stop_regs(task_t *task) {
    if (!task)
        return NULL;

    return &task->ptrace_regs;
}

static inline void ptrace_snapshot_regs(task_t *task,
                                        const struct pt_regs *regs) {
    if (!task || !regs)
        return;

    memcpy(&task->ptrace_regs, regs, sizeof(*regs));
}

static inline uint8_t ptrace_stop_signal(const task_t *task) {
    if (!task)
        return 0;

    return (uint8_t)((task->ptrace_wait_status >> 8) & 0xff);
}

static void ptrace_fill_default_siginfo(siginfo_t *info, int sig) {
    if (!info)
        return;

    memset(info, 0, sizeof(*info));
    info->si_signo = sig;
    info->si_errno = 0;
    info->si_code = SI_KERNEL;
}

static void ptrace_wake_tracer(task_t *task) {
    task_t *tracer;

    if (!ptrace_is_traced(task))
        return;

    tracer = task_find_by_pid(task->ptrace_tracer_pid);
    if (tracer)
        task_unblock(tracer, EOK);
}

static void ptrace_stop_current(task_t *task, const struct pt_regs *regs,
                                int sig, const siginfo_t *info,
                                uint8_t stop_kind) {
    siginfo_t kinfo;

    if (!task || !ptrace_is_traced(task))
        return;

    if (info) {
        memcpy(&kinfo, info, sizeof(kinfo));
    } else {
        ptrace_fill_default_siginfo(&kinfo, sig);
    }

    kinfo.si_signo = sig & 0x7f;

    ptrace_snapshot_regs(task, regs);
    task->ptrace_last_stop = stop_kind;
    task->ptrace_wait_status = (uint32_t)(((sig & 0xff) << 8) | 0x7f);
    task->ptrace_stopped = true;
    task->ptrace_wait_pending = true;
    memcpy(&task->ptrace_siginfo, &kinfo, sizeof(kinfo));

    ptrace_wake_tracer(task);
    task_block(task, TASK_BLOCKING, -1, "ptrace");
}

static uint64_t ptrace_stop_status(const task_t *task) {
    if (!task)
        return 0;

    return task->ptrace_wait_status;
}

static void ptrace_stop_event(task_t *task, uint32_t event, uint64_t message) {
    siginfo_t info;

    if (!task || !ptrace_is_traced(task))
        return;

    memset(&info, 0, sizeof(info));
    info.si_signo = SIGTRAP;
    info.si_errno = 0;
    info.si_code = SI_KERNEL;

    ptrace_snapshot_regs(task, ptrace_task_regs(task));
    task->ptrace_message = message;
    task->ptrace_last_stop = PTRACE_STOP_SIGNAL;
    task->ptrace_wait_status =
        (uint32_t)((SIGTRAP << 8) | 0x7f | ((event & 0xff) << 16));
    task->ptrace_stopped = true;
    task->ptrace_wait_pending = true;
    memcpy(&task->ptrace_siginfo, &info, sizeof(info));

    task->ptrace_syscall_exit_pending = false;
    ptrace_wake_tracer(task);
    task_block(task, TASK_BLOCKING, -1, "ptrace-exec");
}

static uint32_t ptrace_audit_arch(void) {
#if defined(__x86_64__)
    return AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    return AUDIT_ARCH_AARCH64;
#else
    return 0;
#endif
}

static void ptrace_fill_syscall_info(struct ptrace_syscall_info *info,
                                     const struct pt_regs *regs,
                                     uint8_t last_stop) {
    if (!info || !regs)
        return;

    memset(info, 0, sizeof(*info));
    info->arch = ptrace_audit_arch();

#if defined(__x86_64__)
    info->instruction_pointer = regs->rip;
    info->stack_pointer = regs->rsp;

    if (last_stop == PTRACE_STOP_SYSCALL_ENTER) {
        info->op = PTRACE_SYSCALL_INFO_ENTRY;
        info->entry.nr = regs->orig_rax;
        info->entry.args[0] = regs->rdi;
        info->entry.args[1] = regs->rsi;
        info->entry.args[2] = regs->rdx;
        info->entry.args[3] = regs->r10;
        info->entry.args[4] = regs->r8;
        info->entry.args[5] = regs->r9;
    } else if (last_stop == PTRACE_STOP_SYSCALL_EXIT) {
        info->op = PTRACE_SYSCALL_INFO_EXIT;
        info->exit.rval = (int64_t)regs->rax;
        info->exit.is_error = (int64_t)regs->rax < 0;
    }
#elif defined(__aarch64__)
    info->instruction_pointer = regs->pc;
    info->stack_pointer = regs->sp_el0;

    if (last_stop == PTRACE_STOP_SYSCALL_ENTER) {
        info->op = PTRACE_SYSCALL_INFO_ENTRY;
        info->entry.nr = regs->syscallno;
        info->entry.args[0] = regs->x0;
        info->entry.args[1] = regs->x1;
        info->entry.args[2] = regs->x2;
        info->entry.args[3] = regs->x3;
        info->entry.args[4] = regs->x4;
        info->entry.args[5] = regs->x5;
    } else if (last_stop == PTRACE_STOP_SYSCALL_EXIT) {
        info->op = PTRACE_SYSCALL_INFO_EXIT;
        info->exit.rval = (int64_t)regs->x0;
        info->exit.is_error = (int64_t)regs->x0 < 0;
    }
#endif
}

static uint64_t ptrace_copy_regs(task_t *target, void *user_buf) {
    struct pt_regs *regs = ptrace_task_stop_regs(target);

    if (!target || !user_buf || !regs)
        return (uint64_t)-EFAULT;
    if (!target->ptrace_stopped && !target->ptrace_wait_pending)
        return (uint64_t)-ESRCH;

#if defined(__x86_64__)
    x64_user_regs_struct_t user_regs = {
        .r15 = regs->r15,
        .r14 = regs->r14,
        .r13 = regs->r13,
        .r12 = regs->r12,
        .rbp = regs->rbp,
        .rbx = regs->rbx,
        .r11 = regs->r11,
        .r10 = regs->r10,
        .r9 = regs->r9,
        .r8 = regs->r8,
        .rax = regs->rax,
        .rcx = regs->rcx,
        .rdx = regs->rdx,
        .rsi = regs->rsi,
        .rdi = regs->rdi,
        .orig_rax = regs->orig_rax,
        .rip = regs->rip,
        .cs = regs->cs,
        .eflags = regs->rflags,
        .rsp = regs->rsp,
        .ss = regs->ss,
        .fs_base = target->arch_context ? target->arch_context->fsbase : 0,
        .gs_base = target->arch_context ? target->arch_context->gsbase : 0,
        .ds = 0,
        .es = 0,
        .fs = 0,
        .gs = 0,
    };

    if (copy_to_user(user_buf, &user_regs, sizeof(user_regs)))
        return (uint64_t)-EFAULT;
#elif defined(__aarch64__)
    aarch64_user_pt_regs_t user_regs = {
        .regs =
            {
                regs->x0,  regs->x1,  regs->x2,  regs->x3,  regs->x4,
                regs->x5,  regs->x6,  regs->x7,  regs->x8,  regs->x9,
                regs->x10, regs->x11, regs->x12, regs->x13, regs->x14,
                regs->x15, regs->x16, regs->x17, regs->x18, regs->x19,
                regs->x20, regs->x21, regs->x22, regs->x23, regs->x24,
                regs->x25, regs->x26, regs->x27, regs->x28, regs->x29,
                regs->x30,
            },
        .sp = regs->sp_el0,
        .pc = regs->pc,
        .pstate = regs->cpsr,
    };

    if (copy_to_user(user_buf, &user_regs, sizeof(user_regs)))
        return (uint64_t)-EFAULT;
#else
    return (uint64_t)-ENOSYS;
#endif

    return 0;
}

static uint64_t ptrace_copy_regset(task_t *target, void *data, uint64_t note) {
    struct iovec iov;
    size_t full_len;

    if (!data)
        return (uint64_t)-EFAULT;
    if (copy_from_user(&iov, data, sizeof(iov)))
        return (uint64_t)-EFAULT;
    if (note != NT_PRSTATUS || !iov.iov_base)
        return (uint64_t)-EINVAL;

#if defined(__x86_64__)
    full_len = sizeof(x64_user_regs_struct_t);
#elif defined(__aarch64__)
    full_len = sizeof(aarch64_user_pt_regs_t);
#else
    return (uint64_t)-ENOSYS;
#endif

    if (iov.len < full_len)
        return (uint64_t)-EIO;

    if (ptrace_copy_regs(target, iov.iov_base))
        return (uint64_t)-EFAULT;

    iov.len = full_len;
    if (copy_to_user(data, &iov, sizeof(iov)))
        return (uint64_t)-EFAULT;

    return 0;
}

static uint64_t ptrace_copy_siginfo(task_t *target, void *data) {
    if (!target || !data)
        return (uint64_t)-EFAULT;
    if (!target->ptrace_stopped && !target->ptrace_wait_pending)
        return (uint64_t)-EINVAL;
    if (copy_to_user(data, &target->ptrace_siginfo, sizeof(siginfo_t)))
        return (uint64_t)-EFAULT;
    return 0;
}

static uint64_t ptrace_copy_syscall_info(task_t *target, uint64_t size,
                                         void *data) {
    struct pt_regs *regs;
    struct ptrace_syscall_info info;
    size_t copy_len;

    if (!target || !data)
        return (uint64_t)-EFAULT;
    if (target->ptrace_last_stop != PTRACE_STOP_SYSCALL_ENTER &&
        target->ptrace_last_stop != PTRACE_STOP_SYSCALL_EXIT) {
        return 0;
    }

    regs = ptrace_task_stop_regs(target);
    if (!regs)
        return (uint64_t)-EFAULT;

    ptrace_fill_syscall_info(&info, regs, target->ptrace_last_stop);
    copy_len = MIN((size_t)size, sizeof(info));
    if (copy_len == 0)
        return sizeof(info);
    if (copy_to_user(data, &info, copy_len))
        return (uint64_t)-EFAULT;

    return copy_len;
}

static uint64_t ptrace_resume(task_t *target, uint8_t action, uint64_t sig,
                              bool detach) {
    if (!target)
        return (uint64_t)-ESRCH;
    if (!target->ptrace_stopped)
        return (uint64_t)-ESRCH;
    if (sig >= MAXSIG)
        return (uint64_t)-EINVAL;

    target->ptrace_wait_pending = false;
    target->ptrace_stopped = false;
    target->ptrace_wait_status = 0;
    target->ptrace_resume_sig = (uint8_t)sig;

    if (detach) {
        target->ptrace_opts = 0;
        target->ptrace_tracer_pid = 0;
        target->ptrace_resume_action = PTRACE_RESUME_NONE;
        target->ptrace_syscall_exit_pending = false;
        target->ptrace_last_stop = PTRACE_STOP_NONE;
    } else {
        target->ptrace_resume_action = action;
        if (action != PTRACE_RESUME_SYSCALL ||
            target->ptrace_last_stop != PTRACE_STOP_SYSCALL_ENTER) {
            target->ptrace_syscall_exit_pending = false;
        }
    }

    task_unblock(target, EOK);
    return 0;
}

bool ptrace_matches_waiter(const task_t *task, const task_t *waiter) {
    return task && waiter && task->ptrace_tracer_pid == waiter->pid;
}

bool ptrace_has_wait_event(const task_t *task) {
    return task && task->ptrace_wait_pending;
}

bool ptrace_consume_wait_event(task_t *task, int *status, siginfo_t *info,
                               bool nowait) {
    if (!task || !task->ptrace_wait_pending)
        return false;

    if (status)
        *status = (int)ptrace_stop_status(task);

    if (info) {
        memset(info, 0, sizeof(*info));
        info->si_signo = SIGCHLD;
        info->si_errno = 0;
        info->si_code = CLD_TRAPPED;
        info->_sifields._sigchld._pid = task->pid;
        info->_sifields._sigchld._uid = task->uid;
        info->_sifields._sigchld._status = ptrace_stop_signal(task);
    }

    if (!nowait)
        task->ptrace_wait_pending = false;

    return true;
}

void ptrace_resume_from_signal(task_t *task) {
    int sig;

    if (!task)
        return;

    sig = task->ptrace_resume_sig;
    task->ptrace_resume_sig = 0;

    if (sig > 0 && sig < MAXSIG)
        task_commit_signal(task, sig, NULL);
}

void ptrace_on_syscall_enter(struct pt_regs *regs) {
    task_t *self = current_task;
    int stop_sig;

    if (!self || !regs || !ptrace_is_traced(self))
        return;
    if (self->ptrace_resume_action != PTRACE_RESUME_SYSCALL ||
        self->ptrace_syscall_exit_pending) {
        return;
    }

    stop_sig = SIGTRAP;
    if (self->ptrace_opts & PTRACE_O_TRACESYSGOOD)
        stop_sig |= 0x80;

    self->ptrace_syscall_exit_pending = true;
    ptrace_stop_current(self, regs, stop_sig, NULL, PTRACE_STOP_SYSCALL_ENTER);
}

void ptrace_on_syscall_exit(struct pt_regs *regs) {
    task_t *self = current_task;
    int stop_sig;

    if (!self || !regs || !ptrace_is_traced(self))
        return;
    if (self->ptrace_resume_action != PTRACE_RESUME_SYSCALL ||
        !self->ptrace_syscall_exit_pending) {
        return;
    }

    stop_sig = SIGTRAP;
    if (self->ptrace_opts & PTRACE_O_TRACESYSGOOD)
        stop_sig |= 0x80;

    self->ptrace_syscall_exit_pending = false;
    ptrace_stop_current(self, regs, stop_sig, NULL, PTRACE_STOP_SYSCALL_EXIT);
}

void ptrace_stop_for_signal(task_t *task, int sig, const siginfo_t *info) {
    if (!task || !ptrace_is_traced(task))
        return;

    ptrace_stop_current(task, ptrace_task_regs(task), sig, info,
                        PTRACE_STOP_SIGNAL);
}

void ptrace_stop_for_exec(task_t *task) {
    if (!task || !ptrace_is_traced(task))
        return;
    if ((task->ptrace_opts & PTRACE_O_TRACEEXEC) == 0)
        return;

    ptrace_stop_event(task, PTRACE_EVENT_EXEC, 0);
}

uint64_t sys_ptrace(uint64_t request, uint64_t pid, void *addr, void *data) {
    task_t *self = current_task;
    task_t *target = NULL;

    if (!self)
        return (uint64_t)-EINVAL;

    if (request == PTRACE_TRACEME) {
        if (!self->parent || ptrace_is_traced(self))
            return (uint64_t)-EPERM;

        self->ptrace_tracer_pid = task_effective_tgid(self->parent);
        self->ptrace_resume_action = PTRACE_RESUME_CONT;
        self->ptrace_opts = 0;
        self->ptrace_wait_pending = false;
        self->ptrace_stopped = false;
        self->ptrace_wait_status = 0;
        self->ptrace_syscall_exit_pending = false;
        self->ptrace_last_stop = PTRACE_STOP_NONE;
        self->ptrace_resume_sig = 0;
        return 0;
    }

    target = ptrace_find_target(self, pid);
    if (!target)
        return (uint64_t)-ESRCH;

    if (request == PTRACE_ATTACH) {
        if (ptrace_is_traced(target) || !ptrace_task_access_ok(self, target))
            return (uint64_t)-EPERM;

        target->ptrace_tracer_pid = self->pid;
        target->ptrace_resume_action = PTRACE_RESUME_CONT;
        target->ptrace_opts = 0;
        target->ptrace_wait_pending = false;
        target->ptrace_stopped = false;
        target->ptrace_wait_status = 0;
        target->ptrace_syscall_exit_pending = false;
        target->ptrace_last_stop = PTRACE_STOP_NONE;
        target->ptrace_resume_sig = 0;
        task_send_signal(target, SIGSTOP, SI_USER);
        return 0;
    }

    if (!ptrace_matches_waiter(target, self))
        return (uint64_t)-ESRCH;

    switch (request) {
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA: {
        unsigned long value = 0;

        if (read_task_user_memory(target, (uint64_t)addr, &value,
                                  sizeof(value)) < 0) {
            return (uint64_t)-EFAULT;
        }
        return (uint64_t)value;
    }
    case PTRACE_CONT:
        return ptrace_resume(target, PTRACE_RESUME_CONT, (uint64_t)data, false);
    case PTRACE_SYSCALL:
        return ptrace_resume(target, PTRACE_RESUME_SYSCALL, (uint64_t)data,
                             false);
    case PTRACE_DETACH:
        return ptrace_resume(target, PTRACE_RESUME_NONE, (uint64_t)data, true);
    case PTRACE_KILL:
        task_send_signal(target, SIGKILL, SI_USER);
        if (target->ptrace_stopped)
            task_unblock(target, EOK);
        return 0;
    case PTRACE_SETOPTIONS: {
        uint64_t options = (uint64_t)data;
        uint64_t supported = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC |
                             PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL;

        if (options & ~supported)
            return (uint64_t)-EINVAL;
        target->ptrace_opts = (uint32_t)options;
        return 0;
    }
    case PTRACE_GETEVENTMSG:
        if (!data)
            return (uint64_t)-EFAULT;
        if (copy_to_user(data, &target->ptrace_message,
                         sizeof(target->ptrace_message))) {
            return (uint64_t)-EFAULT;
        }
        return 0;
    case PTRACE_GETSIGINFO:
        return ptrace_copy_siginfo(target, data);
    case PTRACE_GETREGS:
        return ptrace_copy_regs(target, data);
    case PTRACE_GETREGSET:
        return ptrace_copy_regset(target, data, (uint64_t)addr);
    case PTRACE_GET_SYSCALL_INFO:
        return ptrace_copy_syscall_info(target, (uint64_t)addr, data);
    default:
        return (uint64_t)-EINVAL;
    }
}
