#include <arch/arch.h>
#include <task/task.h>

uint64_t switch_to_kernel_stack()
{
    return current_task->syscall_stack;
}

void *real_memcpy(void *dst, const void *src, size_t len)
{
    return memcpy(dst, src, len);
}

void syscall_init()
{
    uint64_t efer;

    // 1. 启用 EFER.SCE (System Call Extensions)
    efer = rdmsr(MSR_EFER);
    efer |= 1; // 设置 SCE 位
    wrmsr(MSR_EFER, efer);

    uint16_t cs_sysret_cmp = SELECTOR_USER_CS - 16;
    uint16_t ss_sysret_cmp = SELECTOR_USER_DS - 8;
    uint16_t cs_syscall_cmp = SELECTOR_KERNEL_CS;
    uint16_t ss_syscall_cmp = SELECTOR_KERNEL_DS - 8;

    if (cs_sysret_cmp != ss_sysret_cmp)
    {
        printk("Sysret offset is not valid (1)");
        return;
    }

    if (cs_syscall_cmp != ss_syscall_cmp)
    {
        printk("Syscall offset is not valid (2)");
        return;
    }

    // 2. 设置 STAR MSR
    uint64_t star = 0;
    star = ((uint64_t)(SELECTOR_USER_DS - 8) << 48) | // SYSRET 的基础 CS
           ((uint64_t)SELECTOR_KERNEL_CS << 32);      // SYSCALL 的 CS
    wrmsr(MSR_STAR, star);

    // 3. 设置 LSTAR MSR (系统调用入口点)
    wrmsr(MSR_LSTAR, (uint64_t)syscall_exception);

    // 4. 设置 SYSCALL_MASK MSR (RFLAGS 掩码)
    wrmsr(MSR_SYSCALL_MASK, (1 << 9));
}

uint64_t sys_open(const char *name, uint64_t mode, uint64_t flags)
{
    uint64_t i;
    for (i = 0; i < MAX_FD_NUM; i++)
    {
        if (current_task->fds[i] == NULL)
        {
            break;
        }
    }

    if (i == MAX_FD_NUM)
    {
        return (uint64_t)-EBADFD;
    }

    vfs_node_t node = vfs_open(name);
    if (!node)
    {
        return (uint64_t)-ENOENT;
    }

    current_task->fds[i] = node;

    return i;
}

uint64_t sys_close(uint64_t fd)
{
    if (fd >= MAX_FD_NUM)
    {
        return (uint64_t)-EBADFD;
    }

    current_task->fds[fd] = NULL;

    return 0;
}

void syscall_handler(struct pt_regs *regs, struct pt_regs *user_regs)
{
    regs->rip = regs->rcx;
    regs->rflags = regs->r11;
    regs->cs = SELECTOR_USER_CS;
    regs->ss = SELECTOR_USER_DS;
    regs->rsp = (uint64_t)(user_regs + 1);

    uint64_t idx = regs->rax;

    uint64_t arg1 = regs->rdi;
    uint64_t arg2 = regs->rsi;
    uint64_t arg3 = regs->rdx;
    uint64_t arg4 = regs->r10;
    uint64_t arg5 = regs->r8;
    uint64_t arg6 = regs->r9;

    switch (idx)
    {
    case SYS_OPEN:
        regs->rax = sys_open((const char *)arg1, arg2, arg3);
        break;
    case SYS_CLOSE:
        regs->rax = sys_close(arg1);
        break;

    default:
        break;
    }
}
