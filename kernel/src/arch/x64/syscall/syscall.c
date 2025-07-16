#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/fcntl.h>
#include <mm/mm_syscall.h>
#include <net/net_syscall.h>

uint64_t switch_to_kernel_stack()
{
    if (current_task->call_in_signal)
    {
        return current_task->syscall_stack - STACK_SIZE / 2;
    }
    else
    {
        return current_task->syscall_stack;
    }
}

void *real_memcpy(void *dst, const void *src, size_t len)
{
#if defined(__x86_64__)
    return fast_memcpy(dst, src, len);
#else
    return memcpy(dst, src, len);
#endif
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

// Beware the 65 character limit!
char sysname[] = "Next Aether OS";
char nodename[] = "Aether";
char release[] = BUILD_VERSION;
char version[] = BUILD_VERSION;
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

    uint64_t idx = regs->rax & 0xFFFFFFFF;

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
    case SYS_OPENAT:
        regs->rax = sys_openat(arg1, (const char *)arg2, arg3, arg4);
        break;
    case SYS_CLOSE:
        regs->rax = sys_close(arg1);
        break;
    case SYS_CLOSE_RANGE:
        regs->rax = sys_close_range(arg1, arg2, arg3);
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
    case SYS_PREAD64:
        sys_lseek(arg1, arg4, SEEK_SET);
        regs->rax = sys_read(arg1, (void *)arg2, arg3);
        break;
    case SYS_PWRITE64:
        sys_lseek(arg1, arg4, SEEK_SET);
        regs->rax = sys_write(arg1, (void *)arg2, arg3);
        break;
    case SYS_FSYNC:
        regs->rax = 0;
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
        regs->rax = task_fork(regs, false);
        break;
    case SYS_VFORK:
        regs->rax = task_fork(regs, true);
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
    case SYS_REBOOT:
        regs->rax = sys_reboot(arg1, arg2, arg3, (void *)arg4);
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
        regs->rax = sys_waitpid(arg1, (int *)arg2, arg3);
        break;
    case SYS_PRCTL:
        regs->rax = sys_prctl(arg1, arg2, arg3, arg4, arg5);
        break;
    case SYS_ARCH_PRCTL:
        regs->rax = sys_arch_prctl(arg1, arg2);
        break;
    case SYS_BRK:
        regs->rax = sys_brk(arg1);
        break;
    case SYS_RT_SIGPROCMASK:
        regs->rax = sys_ssetmask(arg1, (sigset_t *)arg2, (sigset_t *)arg3);
        break;
    case SYS_GETDENTS64:
        regs->rax = sys_getdents(arg1, arg2, arg3);
        break;
    case SYS_CHDIR:
        regs->rax = sys_chdir((const char *)arg1);
        break;
    case SYS_FCHDIR:
        regs->rax = sys_fchdir(arg1);
        break;
    case SYS_GETCWD:
        regs->rax = sys_getcwd((char *)arg1, arg2);
        break;
    case SYS_MMAP:
        regs->rax = sys_mmap(arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    case SYS_MREMAP:
        regs->rax = sys_mremap(arg1, arg2, arg3, arg4, arg5);
        break;
    case SYS_MPROTECT:
        regs->rax = 0;
        break;
    case SYS_MUNMAP:
        regs->rax = sys_munmap(arg1, arg2);
        break;
    case SYS_MADVISE:
        regs->rax = 0;
        break;
    case SYS_MINCORE:
        regs->rax = sys_mincore(arg1, arg2, arg3);
        break;
    case SYS_CLOCK_GETTIME:
        switch (arg1)
        {
        case 1: // CLOCK_MONOTONIC
        case 6: // CLOCK_MONOTONIC_COARSE
        case 4: // CLOCK_MONOTONIC_RAW
        {
            if (arg2)
            {
                struct timespec *ts = (struct timespec *)arg2;
                uint64_t nano = nanoTime();
                ts->tv_sec = nano / 1000000000ULL;
                ts->tv_nsec = nano % 1000000000ULL;
            }
            regs->rax = 0;
            break;
        }
        case 0:
        {
            tm time;
            time_read(&time);
            uint64_t timestamp = mktime(&time);

            if (arg2)
            {
                struct timespec *ts = (struct timespec *)arg2;
                ts->tv_sec = timestamp;
                ts->tv_nsec = 0;
            }
            regs->rax = 0;
            break;
        }
        default:
            printk("clock not supported\n");
            regs->rax = (uint64_t)-EINVAL;
            break;
        }
        break;
    case SYS_GETTIMEOFDAY:
        tm time_day;
        time_read(&time_day);
        uint64_t timestamp_day = mktime(&time_day);
        if (arg1)
        {
            struct timespec *ts = (struct timespec *)arg1;
            ts->tv_sec = timestamp_day;
            ts->tv_nsec = 0;
        }
        regs->rax = 0;
        break;
    case SYS_CLOCK_GETRES:
        ((struct timespec *)arg2)->tv_nsec = 1000000;
        regs->rax = 0;
        break;
    case SYS_RT_SIGACTION:
        regs->rax = sys_sigaction(arg1, (sigaction_t *)arg2, (sigaction_t *)arg3);
        break;
    case SYS_RT_SIGSUSPEND:
        regs->rax = sys_sigsuspend((const sigset_t *)arg1);
        break;
    case SYS_KILL:
        regs->rax = sys_kill(arg1, arg2);
        break;
    case SYS_RT_SIGRETURN:
        sys_sigreturn(regs);
        regs->rax = 0;
        break;
    case SYS_FCNTL:
        regs->rax = sys_fcntl(arg1, arg2, arg3);
        break;
    case SYS_FADVISE64:
        regs->rax = sys_fadvise64(arg1, arg2, arg3, arg4);
        break;
    case SYS_SOCKET:
        regs->rax = sys_socket(arg1, arg2, arg3);
        break;
    case SYS_SOCKETPAIR:
        regs->rax = sys_socketpair(arg1, arg2, arg3, (void *)arg4);
        break;
    case SYS_GETSOCKNAME:
        regs->rax = sys_getsockname(arg1, (struct sockaddr_un *)arg2, (socklen_t *)arg3);
        break;
    case SYS_GETPEERNAME:
    {
        int fd = arg1;
        struct sockaddr_un *addr = (struct sockaddr_un *)arg2;
        socklen_t *addrlen = (socklen_t *)arg3;
        regs->rax = sys_getpeername(fd, addr, addrlen);
        break;
    }
    case SYS_BIND:
        regs->rax = sys_bind(arg1, (const struct sockaddr_un *)arg2, arg3);
        break;
    case SYS_LISTEN:
        regs->rax = sys_listen(arg1, arg2);
        break;
    case SYS_ACCEPT:
        regs->rax = sys_accept(arg1, (struct sockaddr_un *)arg2, (socklen_t *)arg3, 0);
        break;
    case SYS_ACCEPT4:
        regs->rax = sys_accept(arg1, (struct sockaddr_un *)arg2, (socklen_t *)arg3, arg4);
        break;
    case SYS_CONNECT:
        regs->rax = sys_connect(arg1, (const struct sockaddr_un *)arg2, arg3);
        break;
    case SYS_SENDTO:
        regs->rax = sys_send(arg1, (const void *)arg2, arg3, arg4, (struct sockaddr_un *)arg5, (socklen_t)arg6);
        break;
    case SYS_RECVFROM:
        regs->rax = sys_recv(arg1, (void *)arg2, arg3, arg4, (struct sockaddr_un *)arg5, (socklen_t *)arg6);
        break;
    case SYS_SENDMSG:
        regs->rax = sys_sendmsg(arg1, (const struct msghdr *)arg2, arg3);
        break;
    case SYS_RECVMSG:
        regs->rax = sys_recvmsg(arg1, (struct msghdr *)arg2, arg3);
        break;
    case SYS_SHUTDOWN:
        regs->rax = sys_shutdown(arg1, arg2);
        break;
    case SYS_SET_TID_ADDRESS:
        regs->rax = current_task->pid;
        break;
    case SYS_POLL:
        regs->rax = sys_poll((struct pollfd *)arg1, arg2, arg3);
        break;
    case SYS_SIGALTSTACK:
        regs->rax = 0;
        break;
    case SYS_GETTID:
        regs->rax = current_task->pid;
        break;
    case SYS_FUTEX:
        regs->rax = sys_futex((int *)arg1, arg2, arg3, (const struct timespec *)arg4, (int *)arg5, arg6);
        break;
    case SYS_PIPE:
        regs->rax = sys_pipe((int *)arg1, 0);
        break;
    case SYS_PIPE2:
        regs->rax = sys_pipe((int *)arg1, arg2);
        break;
    case SYS_STAT:
        regs->rax = sys_stat((const char *)arg1, (struct stat *)arg2);
        break;
    case SYS_LSTAT:
        regs->rax = sys_stat((const char *)arg1, (struct stat *)arg2);
        break;
    case SYS_STATFS:
        regs->rax = 0;
        break;
    case SYS_FSTATFS:
        regs->rax = 0;
        break;
    case SYS_FSTAT:
        regs->rax = sys_fstat(arg1, (struct stat *)arg2);
        break;
    case SYS_NEWFSTATAT:
        regs->rax = sys_newfstatat(arg1, (const char *)arg2, (struct stat *)arg3, arg4);
        break;
    case SYS_STATX:
        regs->rax = sys_statx(arg1, (const char *)arg2, arg3, arg4, (struct statx *)arg5);
        break;
    case SYS_SYSINFO:
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
    case SYS_SETUID:
        current_task->uid = arg1;
        regs->rax = 0;
        break;
    case SYS_SETGID:
        current_task->gid = arg1;
        regs->rax = 0;
        break;
    case SYS_GETRESUID:
        regs->rax = current_task->ruid;
        break;
    case SYS_GETRESGID:
        regs->rax = current_task->rgid;
        break;
    case SYS_SETRESUID:
        current_task->ruid = arg1;
        regs->rax = 0;
        break;
    case SYS_SETRESGID:
        current_task->rgid = arg1;
        regs->rax = 0;
        break;
    case SYS_SETGROUPS:
        regs->rax = 0;
        break;
    case SYS_DUP:
        regs->rax = sys_dup(arg1);
        break;
    case SYS_DUP2:
        regs->rax = sys_dup2(arg1, arg2);
        break;
    case SYS_GETRLIMIT:
        regs->rax = sys_get_rlimit(arg1, (struct rlimit *)arg2);
        break;
    case SYS_PRLIMIT64:
        regs->rax = sys_prlimit64(arg1, arg2, (struct rlimit *)arg3, (struct rlimit *)arg4);
        break;
    case SYS_ACCESS:
        regs->rax = sys_access((char *)arg1, arg2);
        break;
    case SYS_FACCESSAT:
        regs->rax = sys_faccessat(arg1, (const char *)arg2, arg3);
        break;
    case SYS_FACCESSAT2:
        regs->rax = sys_faccessat2(arg1, (const char *)arg2, arg3, arg4);
        break;
    case SYS_SELECT:
        regs->rax = sys_select(arg1, (uint8_t *)arg2, (uint8_t *)arg3, (uint8_t *)arg4, (struct timeval *)arg5);
        break;
    case SYS_PSELECT6:
        regs->rax = sys_pselect6(arg1, (fd_set *)arg2, (fd_set *)arg3, (fd_set *)arg4, (struct timespec *)arg5, (WeirdPselect6 *)arg6);
        break;
    case SYS_READLINK:
        regs->rax = sys_readlink((char *)arg1, (char *)arg2, arg3);
        break;
    case SYS_READLINKAT:
        regs->rax = sys_readlinkat(arg1, (char *)arg2, (char *)arg3, arg4);
        break;
    case SYS_RENAME:
        regs->rax = sys_rename((const char *)arg1, (const char *)arg2);
        break;
    case SYS_RENAMEAT:
        regs->rax = sys_renameat(arg1, (const char *)arg2, arg3, (const char *)arg4);
        break;
    case SYS_UNLINK:
        regs->rax = sys_unlink((const char *)arg1);
        break;
    case SYS_UNLINKAT:
        regs->rax = sys_unlinkat(arg1, (const char *)arg2, arg3);
        break;
    case SYS_MOUNT:
        regs->rax = sys_mount((char *)arg1, (char *)arg2, (char *)arg3, arg4, (void *)arg5);
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
    case SYS_EVENTFD2:
        regs->rax = sys_eventfd2(arg1, arg2);
        break;
    case SYS_SIGNALFD:
        regs->rax = sys_signalfd(arg1, (const sigset_t *)arg2, arg3);
        break;
    case SYS_SIGNALFD4:
        regs->rax = sys_signalfd4(arg1, (const sigset_t *)arg2, arg3, arg4);
        break;
    case SYS_TIMER_CREATE:
        regs->rax = sys_timer_create((clockid_t)arg1, (struct sigevent *)arg2, (timer_t *)arg3);
        break;
    case SYS_TIMER_SETTIME:
        regs->rax = sys_timer_settime((timer_t)arg1, (const struct itimerval *)arg2, (struct itimerval *)arg3);
        break;
    case SYS_TIMERFD_CREATE:
        regs->rax = sys_timerfd_create(arg1, arg2);
        break;
    case SYS_TIMERFD_SETTIME:
        regs->rax = sys_timerfd_settime(arg1, arg2, (const struct itimerval *)arg3, (struct itimerval *)arg4);
        break;
    case SYS_MEMFD_CREATE:
        regs->rax = sys_memfd_create((const char *)arg1, arg2);
        break;
    case SYS_FLOCK:
        regs->rax = sys_flock(arg1, arg2);
        break;
    case SYS_SETFSUID:
        regs->rax = 0;
        break;
    case SYS_SETFSGID:
        regs->rax = 0;
        break;
    case SYS_SETSOCKOPT:
        regs->rax = sys_setsockopt(arg1, arg2, arg3, (const void *)arg4, arg5);
        break;
    case SYS_GETSOCKOPT:
        regs->rax = sys_getsockopt(arg1, arg2, arg3, (void *)arg4, (socklen_t *)arg5);
        break;
    case SYS_SETITIMER:
        regs->rax = sys_setitimer(arg1, (struct itimerval *)arg2, (struct itimerval *)arg3);
        break;
    case SYS_CHOWN:
        regs->rax = 0;
        break;
    case SYS_FCHOWN:
        regs->rax = 0;
        break;
    case SYS_CHMOD:
        regs->rax = 0;
        break;
    case SYS_FCHMOD:
        regs->rax = 0;
        break;
    case SYS_UMASK:
        regs->rax = 0;
        break;
    case SYS_MKDIR:
        regs->rax = sys_mkdir((const char *)arg1, arg2);
        break;
    case SYS_RMDIR:
        regs->rax = sys_unlink((const char *)arg1);
        break;
    case SYS_LINK:
        regs->rax = sys_link((const char *)arg1, (const char *)arg2);
        break;
    case SYS_SYMLINK:
        regs->rax = sys_symlink((const char *)arg1, (const char *)arg2);
        break;
    case SYS_FALLOCATE:
        regs->rax = sys_fallocate(arg1, arg2, arg3, arg4);
        break;
    case SYS_FTRUNCATE:
        regs->rax = 0;
        break;
    case SYS_SETPRIORITY:
        regs->rax = 0;
        break;
    case SYS_UTIMES:
        regs->rax = 0;
        break;
    case SYS_UTIMENSAT:
        regs->rax = 0;
        break;
    case SYS_FUTIMESAT:
        regs->rax = 0;
        break;
    case SYS_SCHED_SETSCHEDULER:
        regs->rax = 0;
        break;
    case SYS_SCHED_SETAFFINITY:
        regs->rax = 0;
        break;
    case SYS_MEMBARRIER:
        regs->rax = 0;
        break;
    case SYS_SETSID:
        regs->rax = current_task->sid;
        break;
    case SYS_SET_ROBUST_LIST:
        regs->rax = 0;
        break;
    case SYS_RSEQ:
        regs->rax = 0;
        break;
    case SYS_SCHED_GETAFFINITY:
        regs->rax = 0;
        break;
    case SYS_GETRANDOM:
        void *buffer = (void *)arg1;
        size_t get_len = (size_t)arg2;
        uint32_t flags = (uint32_t)arg3;

        if (get_len == 0 || get_len > 1024 * 1024)
        {
            regs->rax = (uint64_t)-EINVAL;
            break;
        }

        for (size_t i = 0; i < get_len; i++)
        {
            tm time;
            time_read(&time);
            uint64_t next = mktime(&time);
            next = next * 1103515245 + 12345;
            uint8_t rand_byte = ((uint8_t)(next / 65536) % 32768);
            memcpy(buffer + i, &rand_byte, 1);
        }

        regs->rax = get_len;
        break;
    case SYS_INOTIFY_INIT1:
        regs->rax = 0;
        break;
    case SYS_INOTIFY_ADD_WATCH:
        regs->rax = 0;
        break;
    default:
        regs->rax = (uint64_t)-ENOSYS;
        break;
    }

    if (regs->rax == (uint64_t)-ENOSYS || (uint32_t)regs->rax == (uint32_t)-ENOSYS)
    {
        char buf[32];
        int len = sprintf(buf, "syscall %d not implemented\n", idx);
        serial_printk(buf, len);
    }
}
