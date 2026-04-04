#include <arch/arch.h>
#include <task/task.h>
#include <libs/strerror.h>
#include <arch/x64/syscall/nr.h>
#include <arch/x64/task/arch_context.h>

void syscall_init() {
    uint64_t efer;

    // 1. 启用 EFER.SCE (System Call Extensions)
    efer = rdmsr(MSR_EFER);
    efer |= 1; // 设置 SCE 位
    wrmsr(MSR_EFER, efer);

    uint16_t cs_sysret_cmp = SELECTOR_USER_CS - 16;
    uint16_t ss_sysret_cmp = SELECTOR_USER_DS - 8;
    uint16_t cs_syscall_cmp = SELECTOR_KERNEL_CS;
    uint16_t ss_syscall_cmp = SELECTOR_KERNEL_DS - 8;

    if (cs_sysret_cmp != ss_sysret_cmp) {
        printk("Sysret offset is not valid (1)");
        return;
    }

    if (cs_syscall_cmp != ss_syscall_cmp) {
        printk("Syscall offset is not valid (2)");
        return;
    }

    // 2. 设置 STAR MSR
    uint64_t star = 0;
    star = ((uint64_t)(SELECTOR_USER_DS - 8) << 48) | // SYSRET 的基础 CS
           ((uint64_t)SELECTOR_KERNEL_CS << 32);      // SYSCALL 的 CS
    wrmsr(MSR_STAR, star);

    // 3. 设置 LSTAR MSR (系统调用入口点)
    wrmsr(MSR_LSTAR, (uint64_t)syscall_handler_asm);

    // 4. 设置 SYSCALL_MASK MSR (RFLAGS 掩码)
    wrmsr(MSR_SYSCALL_MASK, (1 << 9));
}

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM];

void syscall_handler_init() {
    memset(syscall_handlers, 0, sizeof(syscall_handlers));
}

spinlock_t syscall_debug_lock = SPIN_INIT;

static inline uint64_t syscall_account_running_ns(task_t *task,
                                                  uint64_t now_ns) {
    if (!task || !task->last_sched_in_ns || now_ns <= task->last_sched_in_ns)
        return 0;
    uint64_t delta = now_ns - task->last_sched_in_ns;
    task->user_time_ns += delta;
    task->last_sched_in_ns = now_ns;
    return delta;
}

void syscall_handler(struct pt_regs *regs, uint64_t user_rsp) {
    uint64_t idx = regs->rax & 0xFFFFFFFF;

    regs->rip = regs->rcx;
    regs->rflags = regs->r11;
    regs->rflags |= (1 << 9);
    regs->cs = SELECTOR_USER_CS;
    regs->ss = SELECTOR_USER_DS;
    regs->rsp = user_rsp;
    regs->orig_rax = regs->rax;

    task_t *self = current_task;
    if (!self) {
        regs->rax = (uint64_t)-ENOSYS;
        goto done;
    }

    task_membarrier_checkpoint(self);

    uint64_t arg1 = regs->rdi;
    uint64_t arg2 = regs->rsi;
    uint64_t arg3 = regs->rdx;
    uint64_t arg4 = regs->r10;
    uint64_t arg5 = regs->r8;
    uint64_t arg6 = regs->r9;

    if (self)
        syscall_account_running_ns(self, nano_time());
    uint64_t syscall_user_base = self ? self->user_time_ns : 0;

    if (idx >= MAX_SYSCALL_NUM) {
        regs->rax = (uint64_t)-ENOSYS;
        goto done;
    }

    syscall_handle_t handler = syscall_handlers[idx];
    regs->func = (uint64_t)handler;
    if (!handler) {
        regs->rax = (uint64_t)-ENOSYS;
        goto done;
    }

    if (idx == SYS_FORK || idx == SYS_VFORK || idx == SYS_CLONE ||
        idx == SYS_CLONE3 || idx == SYS_RT_SIGRETURN) {
        special_syscall_handle_t h = (special_syscall_handle_t)handler;
        regs->rax = h(regs, arg1, arg2, arg3, arg4, arg5, arg6);
    } else {
        regs->rax = handler(arg1, arg2, arg3, arg4, arg5, arg6);
    }

    if ((idx != SYS_BRK) && (idx != SYS_MMAP) && (idx != SYS_MREMAP) &&
        (idx != SYS_SHMAT) && (idx != SYS_RT_SIGRETURN) && (int)regs->rax < 0 &&
        !((int64_t)regs->rax < 0))
        regs->rax |= 0xffffffff00000000;

#define SYSCALL_DEBUG 0
#if SYSCALL_DEBUG
    if (idx == SYS_PAUSE || idx == SYS_SCHED_YIELD)
        goto done;

    bool usable = idx < (sizeof(linux_syscalls) / sizeof(linux_syscalls[0]));
    const LINUX_SYSCALL *info = usable ? &linux_syscalls[idx] : NULL;

    char buf[256];
    int len;

    spin_lock(&syscall_debug_lock);

    len = sprintf(buf, "%d [syscall %d] %s(", self->pid, idx,
                  usable ? info->name : "???");
    serial_printk(buf, len);
    if (usable) {
        if (info->arg1[0]) {
            len = sprintf(buf, "%s:0x%lx,", info->arg1, arg1);
            serial_printk(buf, len);
        }
        if (info->arg2[0]) {
            len = sprintf(buf, "%s:0x%lx,", info->arg2, arg2);
            serial_printk(buf, len);
        }
        if (info->arg3[0]) {
            len = sprintf(buf, "%s:0x%lx,", info->arg3, arg3);
            serial_printk(buf, len);
        }
        if (info->arg4[0]) {
            len = sprintf(buf, "%s:0x%lx,", info->arg4, arg4);
            serial_printk(buf, len);
        }
        if (info->arg5[0]) {
            len = sprintf(buf, "%s:0x%lx,", info->arg5, arg5);
            serial_printk(buf, len);
        }
        if (info->arg6[0]) {
            len = sprintf(buf, "%s:0x%lx,", info->arg6, arg6);
            serial_printk(buf, len);
        }
    }
    if ((int64_t)regs->rax < 0) {
        len = sprintf(buf, ") = %s%s%s\n", "ERR(", strerror(-regs->rax), ")");
    } else {
        len = sprintf(buf, ") = %#018lx\n", regs->rax);
    }
    serial_printk(buf, len);

    spin_unlock(&syscall_debug_lock);
#endif

done:
    if (self) {
        syscall_account_running_ns(self, nano_time());
        if (self->user_time_ns > syscall_user_base)
            self->system_time_ns += self->user_time_ns - syscall_user_base;
    }

    if (idx != SYS_BRK && idx != SYS_RSEQ && regs->rax == (uint64_t)-ENOSYS) {
        serial_fprintk("syscall %d not implemented\n", idx);
    }
    if (regs->rax == (uint64_t)-EFAULT) {
        serial_fprintk("syscall %d accessed a invalid address\n", idx);
    }

    if (self && self->signal && self->signal->signal != 0)
        task_signal(regs);

    regs->rcx = regs->rip;
    regs->r11 = regs->rflags;
}
