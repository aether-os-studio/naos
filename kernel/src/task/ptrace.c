#include <task/ptrace.h>
#include <task/task_syscall.h>

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

bool ptrace_tracees_fork_enabled(task_t *task, uint64_t clone_flags,
                                 uint32_t *event_out) {
    uint32_t event = 0;

    if (!task || !ptrace_is_traced(task))
        return false;

    if (clone_flags & CLONE_VFORK) {
        if (task->ptrace_opts & PTRACE_O_TRACEVFORK)
            event = PTRACE_EVENT_VFORK;
    } else if (clone_flags & CLONE_THREAD) {
        if (task->ptrace_opts & PTRACE_O_TRACECLONE)
            event = PTRACE_EVENT_CLONE;
    } else {
        if (task->ptrace_opts & PTRACE_O_TRACEFORK)
            event = PTRACE_EVENT_FORK;
    }

    if (!event)
        return false;

    if (event_out)
        *event_out = event;
    return true;
}

void ptrace_attach_child(task_t *parent, task_t *child) {
    if (!parent || !child || !ptrace_is_traced(parent))
        return;

    child->ptrace_tracer_pid = parent->ptrace_tracer_pid;
    child->ptrace_resume_action = PTRACE_RESUME_CONT;
    child->ptrace_opts = parent->ptrace_opts;
    child->ptrace_wait_pending = true;
    child->ptrace_stopped = true;
    child->ptrace_wait_status = (uint32_t)((SIGSTOP << 8) | 0x7f);
    child->ptrace_syscall_exit_pending = false;
    child->ptrace_exec_event_pending = false;
    child->ptrace_last_stop = PTRACE_STOP_SIGNAL;
    child->ptrace_resume_sig = 0;
    child->ptrace_message = 0;
    ptrace_fill_default_siginfo(&child->ptrace_siginfo, SIGSTOP);
}

void ptrace_stop_for_fork_event(task_t *task, uint32_t event,
                                uint64_t message) {
    if (!task || !ptrace_is_traced(task))
        return;
    if (event != PTRACE_EVENT_FORK && event != PTRACE_EVENT_VFORK &&
        event != PTRACE_EVENT_CLONE) {
        return;
    }

    ptrace_stop_event(task, event, message);
}

static void ptrace_fill_syscall_info(struct ptrace_syscall_info *info,
                                     const struct pt_regs *regs,
                                     uint8_t last_stop) {
    if (!info || !regs)
        return;

    memset(info, 0, sizeof(*info));
    info->arch = arch_ptrace_audit_arch();
    arch_ptrace_fill_syscall_info(info, regs, last_stop);
}

static uint64_t ptrace_copy_regs(task_t *target, void *user_buf) {
    struct pt_regs *regs = ptrace_task_stop_regs(target);

    if (!target || !user_buf || !regs)
        return (uint64_t)-EFAULT;
    if (!target->ptrace_stopped && !target->ptrace_wait_pending)
        return (uint64_t)-ESRCH;

    return arch_ptrace_copy_regs(target, regs, user_buf);
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

    full_len = arch_ptrace_regset_size();
    if (full_len == 0)
        return (uint64_t)-ENOSYS;

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
        target->ptrace_exec_event_pending = false;
        target->ptrace_last_stop = PTRACE_STOP_NONE;
    } else {
        target->ptrace_resume_action = action;
        if (target->ptrace_exec_event_pending) {
            if (action != PTRACE_RESUME_SYSCALL)
                target->ptrace_exec_event_pending = false;
        } else if (action != PTRACE_RESUME_SYSCALL ||
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

    self->ptrace_exec_event_pending = false;
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
    uint64_t old_pid;

    if (!task || !ptrace_is_traced(task))
        return;
    if ((task->ptrace_opts & PTRACE_O_TRACEEXEC) == 0)
        return;

    old_pid = task->pid;
    task->ptrace_exec_event_pending = task->ptrace_syscall_exit_pending;
    ptrace_stop_event(task, PTRACE_EVENT_EXEC, old_pid);
}

void ptrace_stop_for_exec_syscall_exit(task_t *task) {
    struct pt_regs *regs;
    int stop_sig;

    if (!task || !ptrace_is_traced(task))
        return;
    if (task->ptrace_resume_action != PTRACE_RESUME_SYSCALL ||
        !task->ptrace_exec_event_pending) {
        return;
    }

    regs = ptrace_task_regs(task);
    if (!regs)
        return;

    stop_sig = SIGTRAP;
    if (task->ptrace_opts & PTRACE_O_TRACESYSGOOD)
        stop_sig |= 0x80;

    task->ptrace_exec_event_pending = false;
    task->ptrace_syscall_exit_pending = false;
    ptrace_stop_current(task, regs, stop_sig, NULL, PTRACE_STOP_SYSCALL_EXIT);
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
        self->ptrace_exec_event_pending = false;
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
        target->ptrace_exec_event_pending = false;
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
        uint64_t supported = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                             PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                             PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT |
                             PTRACE_O_EXITKILL;

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
