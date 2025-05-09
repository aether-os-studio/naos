#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <mm/mm_syscall.h>
#include <net/net_syscall.h>

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

extern int sys_pipe(int pipefd[2]);

// Beware the 65 character limit!
char sysname[] = "Next Aether OS";
char nodename[] = "Aether";
char release[] = "0.0.1";
char version[] = "0.0.1";
char machine[] = "x86_64";

void syscall_handler(struct pt_regs *regs, struct pt_regs *user_regs)
{
    regs->rip = regs->rcx;
    regs->rflags = regs->r11;
    regs->cs = SELECTOR_USER_CS;
    regs->ss = SELECTOR_USER_DS;
    regs->ds = SELECTOR_USER_DS;
    regs->es = SELECTOR_USER_DS;
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
    case SYS_LSEEK:
        regs->rax = sys_lseek(arg1, arg2, arg3);
        break;
    case SYS_READ:
        regs->rax = sys_read(arg1, (void *)arg2, arg3);
        break;
    case SYS_WRITE:
        regs->rax = sys_write(arg1, (const void *)arg2, arg3);
        break;
    case SYS_IOCTL:
        regs->rax = sys_ioctl(arg1, arg2, arg3);
        break;
    case SYS_READV:
        regs->rax = sys_readv(arg1, (struct iovec *)arg2, arg3);
        break;
    case SYS_WRITEV:
        regs->rax = sys_writev(arg1, (struct iovec *)arg2, arg3);
        break;
    case SYS_CLONE:
        regs->rax = sys_clone(regs, arg1, arg2, (int *)arg3, (int *)arg4, arg5);
        break;
    case SYS_FORK:
        regs->rax = task_fork(regs);
        break;
    case SYS_EXECVE:
        regs->rax = task_execve((const char *)arg1, (const char **)arg2, (const char **)arg3);
        break;
    case SYS_EXIT:
        regs->rax = task_exit((int64_t)arg1);
        break;
    case SYS_EXIT_GROUP:
        regs->rax = task_exit((int64_t)arg1);
        break;
    case SYS_GETPID:
        if (arg1 == UINT64_MAX && arg2 == UINT64_MAX && arg3 == UINT64_MAX && arg4 == UINT64_MAX && arg5 == UINT64_MAX)
            regs->rax = 1;
        else
            regs->rax = current_task->pid;
        break;
    case SYS_GETPPID:
        regs->rax = current_task->ppid;
        break;
    case SYS_WAIT4:
        regs->rax = sys_waitpid(arg1, (int *)arg2);
        break;
    case SYS_ARCH_PRCTL:
        regs->rax = sys_arch_prctl(arg1, arg2);
        break;
    case SYS_BRK:
        regs->rax = sys_brk(arg1);
        break;
    case SYS_SIGNAL:
        regs->rax = sys_signal(arg1, arg2, arg3);
        break;
    case SYS_SETMASK:
        regs->rax = sys_ssetmask(arg1, (sigset_t *)arg2, (sigset_t *)arg3);
        break;
    case SYS_GETDENTS64:
        regs->rax = sys_getdents(arg1, arg2, arg3);
        break;
    case SYS_CHDIR:
        regs->rax = sys_chdir((const char *)arg1);
        break;
    case SYS_GETCWD:
        regs->rax = sys_getcwd((char *)arg1, arg2);
        break;
    case SYS_MMAP:
        regs->rax = sys_mmap(arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    case SYS_MPROTECT:
        regs->rax = 0;
        break;
    case SYS_MUNMAP:
        regs->rax = 0;
        break;
    case SYS_CLOCK_GETTIME:
        tm time;
        time_read_bcd(&time);
        if (arg1)
            *(int64_t *)arg1 = mktime(&time);
        if (arg2)
            *(int64_t *)arg2 = 0;
        regs->rax = 0;
        break;
    case SYS_CLOCK_GETRES:
        ((struct timespec *)arg2)->tv_nsec = 1000000;
        regs->rax = 0;
        break;
    case SYS_SIGACTION:
        regs->rax = sys_sigaction(arg1, (sigaction_t *)arg2, (sigaction_t *)arg3);
        break;
    case SYS_SIGPROCMASK:
        regs->rax = sys_ssetmask(arg1, (sigset_t *)arg2, (sigset_t *)arg3);
        break;
    case SYS_KILL:
        regs->rax = sys_kill(arg1, arg2);
        break;
    case SYS_SIGRETURN:
        sys_sigreturn();
        regs->rax = 0;
        break;
    case SYS_FCNTL:
        regs->rax = sys_fcntl(arg1, arg2, arg3);
        break;
    case SYS_SOCKET:
        regs->rax = sys_socket(arg1, arg2, arg3);
        break;
    case SYS_BIND:
        regs->rax = sys_bind(arg1, (const struct sockaddr *)arg2, arg3);
        break;
    case SYS_LISTEN:
        regs->rax = sys_listen(arg1, arg2);
        break;
    case SYS_ACCEPT:
        regs->rax = sys_accept(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3);
        break;
    case SYS_CONNECT:
        regs->rax = sys_connect(arg1, (const struct sockaddr *)arg2, arg3);
        break;
    case SYS_SENDTO:
        regs->rax = sys_send(arg1, (const void *)arg2, arg3, arg4);
        break;
    case SYS_RECVFROM:
        regs->rax = sys_recv(arg1, (void *)arg2, arg3, arg4);
        break;
    case SYS_SET_TID_ADDRESS:
        regs->rax = current_task->pid;
        break;
    case SYS_POLL:
        regs->rax = 0;
        break;
    case SYS_SIGALTSTACK:
        regs->rax = 0;
        break;
    case SYS_GETTID:
        regs->rax = current_task->pid;
        break;
    case SYS_FUTEX:
        regs->rax = 0;
        break;
    case SYS_PIPE:
    case SYS_PIPE2:
        // todo: support flags
        regs->rax = sys_pipe((int *)arg1);
        break;
    case SYS_STAT:
        regs->rax = sys_stat((const char *)arg1, (struct stat *)arg2);
        break;
    case SYS_FSTAT:
        regs->rax = sys_fstat(arg1, (struct stat *)arg2);
        break;
    case SYS_UNAME:
        struct utsname *utsname = (struct utsname *)arg1;
        memcpy(utsname->sysname, sysname, sizeof(sysname));
        memcpy(utsname->nodename, nodename, sizeof(nodename));
        memcpy(utsname->release, release, sizeof(release));
        memcpy(utsname->version, version, sizeof(version));
        memcpy(utsname->machine, machine, sizeof(machine));
        regs->rax = 0;
        break;
    case SYS_GETUID:
        regs->rax = current_task->uid;
        break;
    case SYS_GETGID:
        regs->rax = current_task->gid;
        break;
    case SYS_GETEUID:
        regs->rax = current_task->euid;
        break;
    case SYS_GETEGID:
        regs->rax = current_task->egid;
        break;
    case SYS_SETPGID:
        if (!arg1)
        {
            current_task->pgid = (int64_t)arg2;
        }
        else
        {
            if (tasks[arg1] == NULL)
            {
                regs->rax = (uint64_t)-ENOENT;
                break;
            }
            tasks[arg1]->pgid = arg2;
        }
        regs->rax = 0;
        break;
    case SYS_GETPGID:
        regs->rax = current_task->pgid;
        break;
    case SYS_DUP:
        regs->rax = 0;
        break;
    case SYS_DUP2:
        regs->rax = 0;
        break;
    case SYS_GETRLIMIT:
        regs->rax = sys_get_rlimit(arg1, (struct rlimit *)arg2);
        break;
    case SYS_PRLIMIT64:
        regs->rax = 0;
        break;
    case SYS_ACCESS:
        regs->rax = sys_access((char *)arg1, arg2);
        break;
    case SYS_FACCESSAT:
        regs->rax = sys_faccessat(arg1, (const char *)arg2, arg3);
        break;
    case SYS_SELECT:
        regs->rax = sys_select(arg1, (fd_set *)arg2, (fd_set *)arg3, (fd_set *)arg4, (struct timespec *)arg5);
        break;
    case SYS_PSELECT6:
        regs->rax = sys_pselect6(arg1, (fd_set *)arg2, (fd_set *)arg3, (fd_set *)arg4, (struct timespec *)arg5, (WeirdPselect6 *)arg6);
        break;
    case SYS_READLINK:
        regs->rax = sys_readlink((char *)arg1, (char *)arg2, arg3);
        break;
    case SYS_NANOSLEEP:
        regs->rax = sys_nanosleep((struct timespec *)arg1, (struct timespec *)arg2);
        break;
    case SYS_EPOLL_CREATE1:
        regs->rax = sys_epoll_create1(arg1);
        break;
    case SYS_EPOLL_CREATE:
        regs->rax = sys_epoll_create(arg1);
        break;
    case SYS_EPOLL_CTL:
        regs->rax = sys_epoll_ctl(arg1, arg2, arg3, (struct epoll_event *)arg4);
        break;
    case SYS_EPOLL_PWAIT:
        regs->rax = sys_epoll_pwait(arg1, (struct epoll_event *)arg2, arg3, arg4, (sigset_t *)arg5, arg6);
        break;
    case SYS_EPOLL_WAIT:
        regs->rax = sys_epoll_wait(arg1, (struct epoll_event *)arg2, arg3, arg4);
        break;
    case SYS_LINK:
        regs->rax = sys_link((const char *)arg1, (const char *)arg2);
        break;

    default:
        regs->rax = (uint64_t)-ENOSYS;
        break;
    }
}
