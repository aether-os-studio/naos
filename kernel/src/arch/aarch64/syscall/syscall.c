#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/fcntl.h>
#include <mm/mm_syscall.h>
#include <net/net_syscall.h>

void syscall_init()
{
}

extern int sys_pipe(int pipefd[2]);

// Beware the 65 character limit!
char sysname[] = "Next Aether OS";
char nodename[] = "Aether";
char release[] = BUILD_VERSION;
char version[] = BUILD_VERSION;
char machine[] = "x86_64";

void aarch64_do_syscall(struct pt_regs *frame)
{
    uint64_t ret = 0;

    uint64_t idx = frame->x8;
    uint64_t arg1 = frame->x0;
    uint64_t arg2 = frame->x1;
    uint64_t arg3 = frame->x2;
    uint64_t arg4 = frame->x3;
    uint64_t arg5 = frame->x4;
    uint64_t arg6 = frame->x5;

    switch (idx)
    {
    case SYS_OPENAT:
        frame->x0 = sys_openat(arg1, (const char *)arg2, arg3, arg4);
        break;
    case SYS_CLOSE:
        frame->x0 = sys_close(arg1);
        break;
    case SYS_LSEEK:
        frame->x0 = sys_lseek(arg1, arg2, arg3);
        break;
    case SYS_READ:
        frame->x0 = sys_read(arg1, (void *)arg2, arg3);
        break;
    case SYS_WRITE:
        frame->x0 = sys_write(arg1, (const void *)arg2, arg3);
        break;
    case SYS_PREAD64:
        sys_lseek(arg1, arg4, SEEK_SET);
        frame->x0 = sys_read(arg1, (void *)arg2, arg3);
        break;
    case SYS_PWRITE64:
        sys_lseek(arg1, arg4, SEEK_SET);
        frame->x0 = sys_write(arg1, (void *)arg2, arg3);
        break;
    case SYS_IOCTL:
        frame->x0 = sys_ioctl(arg1, arg2, arg3);
        break;
    case SYS_READV:
        frame->x0 = sys_readv(arg1, (struct iovec *)arg2, arg3);
        break;
    case SYS_WRITEV:
        frame->x0 = sys_writev(arg1, (struct iovec *)arg2, arg3);
        break;
    case SYS_CLONE:
        frame->x0 = sys_clone(frame, arg1, arg2, (int *)arg3, (int *)arg4, arg5);
        break;
    case SYS_EXECVE:
        frame->x0 = task_execve((const char *)arg1, (const char **)arg2, (const char **)arg3);
        break;
    case SYS_EXIT:
        frame->x0 = task_exit((int64_t)arg1);
        break;
    case SYS_EXIT_GROUP:
        frame->x0 = task_exit((int64_t)arg1);
        break;
    case SYS_GETPID:
        if (arg1 == UINT64_MAX && arg2 == UINT64_MAX && arg3 == UINT64_MAX && arg4 == UINT64_MAX && arg5 == UINT64_MAX)
            frame->x0 = 1;
        else
            frame->x0 = current_task->pid;
        break;
    case SYS_GETPPID:
        frame->x0 = current_task->ppid;
        break;
    case SYS_WAIT4:
        frame->x0 = sys_waitpid(arg1, (int *)arg2, arg3);
        break;
    case SYS_PRCTL:
        frame->x0 = sys_prctl(arg1, arg2, arg3, arg4, arg5);
        break;
    // case SYS_ARCH_PRCTL:
    //     frame->x0 = sys_arch_prctl(arg1, arg2);
    //     break;
    case SYS_BRK:
        frame->x0 = sys_brk(arg1);
        break;
    case SYS_RT_SIGPROCMASK:
        frame->x0 = sys_ssetmask(arg1, (sigset_t *)arg2, (sigset_t *)arg3);
        break;
    case SYS_GETDENTS64:
        frame->x0 = sys_getdents(arg1, arg2, arg3);
        break;
    case SYS_CHDIR:
        frame->x0 = sys_chdir((const char *)arg1);
        break;
    case SYS_FCHDIR:
        frame->x0 = sys_fchdir(arg1);
        break;
    case SYS_GETCWD:
        frame->x0 = sys_getcwd((char *)arg1, arg2);
        break;
    case SYS_MMAP:
        frame->x0 = sys_mmap(arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    case SYS_MPROTECT:
        frame->x0 = 0;
        break;
    case SYS_MUNMAP:
        frame->x0 = 0;
        break;
    case SYS_CLOCK_GETTIME:
        tm time;
        time_read(&time);
        uint64_t timestamp = mktime(&time);
        switch (arg1)
        {
        case 1: // <- todo
        case 6: // CLOCK_MONOTONIC_COARSE
        case 4: // CLOCK_MONOTONIC_RAW
        case 0:
        {
            if (arg2)
            {
                struct timespec *ts = (struct timespec *)arg2;
                ts->tv_sec = timestamp;
                ts->tv_nsec = 0;
            }
            frame->x0 = 0;
            break;
        }
        default:
            printk("clock not supported\n");
            frame->x0 = (uint64_t)-EINVAL;
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
        frame->x0 = 0;
        break;
    case SYS_CLOCK_GETRES:
        ((struct timespec *)arg2)->tv_nsec = 1000000;
        frame->x0 = 0;
        break;
    case SYS_RT_SIGACTION:
        frame->x0 = sys_sigaction(arg1, (sigaction_t *)arg2, (sigaction_t *)arg3);
        break;
    case SYS_RT_SIGSUSPEND:
        frame->x0 = sys_sigsuspend((const sigset_t *)arg1);
        break;
    case SYS_KILL:
        frame->x0 = sys_kill(arg1, arg2);
        break;
    case SYS_RT_SIGRETURN:
        sys_sigreturn();
        frame->x0 = 0;
        break;
    case SYS_FCNTL:
        frame->x0 = sys_fcntl(arg1, arg2, arg3);
        break;
    case SYS_SOCKET:
        frame->x0 = sys_socket(arg1, arg2, arg3);
        break;
    case SYS_SOCKETPAIR:
        frame->x0 = sys_socketpair(arg1, arg2, arg3, (void *)arg4);
        break;
    case SYS_GETSOCKNAME:
        frame->x0 = sys_getsockname(arg1, (struct sockaddr_un *)arg2, (socklen_t *)arg3);
        break;
    case SYS_GETPEERNAME:
    {
        int fd = arg1;
        struct sockaddr_un *addr = (struct sockaddr_un *)arg2;
        socklen_t *addrlen = (socklen_t *)arg3;
        frame->x0 = sys_getpeername(fd, addr, addrlen);
        break;
    }
    case SYS_BIND:
        frame->x0 = sys_bind(arg1, (const struct sockaddr_un *)arg2, arg3);
        break;
    case SYS_LISTEN:
        frame->x0 = sys_listen(arg1, arg2);
        break;
    case SYS_ACCEPT:
        frame->x0 = sys_accept(arg1, (struct sockaddr_un *)arg2, (socklen_t *)arg3);
        break;
    case SYS_CONNECT:
        frame->x0 = sys_connect(arg1, (const struct sockaddr_un *)arg2, arg3);
        break;
    case SYS_SENDTO:
        frame->x0 = sys_send(arg1, (const void *)arg2, arg3, arg4, (struct sockaddr_un *)arg5, (socklen_t)arg6);
        break;
    case SYS_RECVFROM:
        frame->x0 = sys_recv(arg1, (void *)arg2, arg3, arg4, (struct sockaddr_un *)arg5, (socklen_t *)arg6);
        break;
    case SYS_SENDMSG:
        frame->x0 = sys_sendmsg(arg1, (const struct msghdr *)arg2, arg3);
        break;
    case SYS_RECVMSG:
        frame->x0 = sys_recvmsg(arg1, (struct msghdr *)arg2, arg3);
        break;
    case SYS_SHUTDOWN:
        frame->x0 = sys_shutdown(arg1, arg2);
        break;
    case SYS_SET_TID_ADDRESS:
        frame->x0 = current_task->pid;
        break;
    case SYS_SIGALTSTACK:
        frame->x0 = 0;
        break;
    case SYS_GETTID:
        frame->x0 = current_task->pid;
        break;
    case SYS_FUTEX:
        frame->x0 = 0;
        break;
    case SYS_PIPE2:
        // todo: support flags
        frame->x0 = sys_pipe((int *)arg1);
        break;
    case SYS_STATFS:
        frame->x0 = 0;
        break;
    case SYS_FSTAT:
        frame->x0 = sys_fstat(arg1, (struct stat *)arg2);
        break;
    case SYS_FSTATAT:
        frame->x0 = sys_newfstatat(arg1, (const char *)arg2, (struct stat *)arg3, arg4);
        break;
    case SYS_STATX:
        frame->x0 = sys_statx(arg1, (const char *)arg2, arg3, arg4, (struct statx *)arg5);
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
        frame->x0 = 0;
        break;
    case SYS_GETUID:
        frame->x0 = current_task->uid;
        break;
    case SYS_GETGID:
        frame->x0 = current_task->gid;
        break;
    case SYS_GETEUID:
        frame->x0 = current_task->euid;
        break;
    case SYS_GETEGID:
        frame->x0 = current_task->egid;
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
                frame->x0 = (uint64_t)-ENOENT;
                break;
            }
            tasks[arg1]->pgid = arg2;
        }
        frame->x0 = 0;
        break;
    case SYS_GETPGID:
        frame->x0 = current_task->pgid;
        break;
    case SYS_SETUID:
        current_task->uid = arg1;
        frame->x0 = 0;
        break;
    case SYS_SETGID:
        current_task->gid = arg1;
        frame->x0 = 0;
        break;
    case SYS_DUP:
        frame->x0 = sys_dup(arg1);
        break;
    case SYS_DUP3:
        frame->x0 = sys_dup3(arg1, arg2, arg3);
        break;
    case SYS_GETRLIMIT:
        frame->x0 = sys_get_rlimit(arg1, (struct rlimit *)arg2);
        break;
    case SYS_PRLIMIT64:
        frame->x0 = sys_prlimit64(arg1, arg2, (struct rlimit *)arg3, (struct rlimit *)arg4);
        break;
    case SYS_FACCESSAT:
        frame->x0 = sys_faccessat(arg1, (const char *)arg2, arg3);
        break;
    case SYS_FACCESSAT2:
        frame->x0 = sys_faccessat2(arg1, (const char *)arg2, arg3, arg4);
        break;
    case SYS_PSELECT6:
        frame->x0 = sys_pselect6(arg1, (fd_set *)arg2, (fd_set *)arg3, (fd_set *)arg4, (struct timespec *)arg5, (WeirdPselect6 *)arg6);
        break;
    case SYS_UNLINKAT:
        frame->x0 = sys_unlinkat(arg1, (const char *)arg2, arg3);
        break;
    case SYS_NANOSLEEP:
        frame->x0 = sys_nanosleep((struct timespec *)arg1, (struct timespec *)arg2);
        break;
    case SYS_EPOLL_CREATE1:
        frame->x0 = sys_epoll_create1(arg1);
        break;
    case SYS_EPOLL_CTL:
        frame->x0 = sys_epoll_ctl(arg1, arg2, arg3, (struct epoll_event *)arg4);
        break;
    case SYS_EPOLL_PWAIT:
        frame->x0 = sys_epoll_pwait(arg1, (struct epoll_event *)arg2, arg3, arg4, (sigset_t *)arg5, arg6);
        break;
    case SYS_PPOLL:
        frame->x0 = sys_ppoll((struct pollfd *)arg1, arg2, (struct timespec *)arg3, (sigset_t *)arg4, arg5);
        break;
    case SYS_EVENTFD2:
        frame->x0 = sys_eventfd2(arg1, arg2);
        break;
    case SYS_SIGNALFD4:
        frame->x0 = sys_signalfd4(arg1, (const sigset_t *)arg2, arg3, arg4);
        break;
    case SYS_TIMER_CREATE:
        frame->x0 = sys_timer_create((clockid_t)arg1, (struct sigevent *)arg2, (timer_t *)arg3);
        break;
    case SYS_TIMER_SETTIME:
        frame->x0 = sys_timer_settime((timer_t)arg1, (const struct itimerval *)arg2, (struct itimerval *)arg3);
        break;
    case SYS_TIMERFD_CREATE:
        frame->x0 = sys_timerfd_create(arg1, arg2);
        break;
    case SYS_TIMERFD_SETTIME:
        frame->x0 = sys_timerfd_settime(arg1, arg2, (const struct itimerval *)arg3, (struct itimerval *)arg4);
        break;
    case SYS_FLOCK:
        frame->x0 = sys_flock(arg1, arg2);
        break;
    case SYS_SETFSUID:
        frame->x0 = 0;
        break;
    case SYS_SETFSGID:
        frame->x0 = 0;
        break;
    case SYS_SETSOCKOPT:
        frame->x0 = sys_setsockopt(arg1, arg2, arg3, (const void *)arg4, arg5);
        break;
    case SYS_GETSOCKOPT:
        frame->x0 = sys_getsockopt(arg1, arg2, arg3, (void *)arg4, (socklen_t *)arg5);
        break;
    case SYS_SETRESUID:
        frame->x0 = 0;
        break;
    case SYS_GETRESUID:
        frame->x0 = 0;
        break;
    case SYS_SETITIMER:
        frame->x0 = sys_setitimer(arg1, (struct itimerval *)arg2, (struct itimerval *)arg3);
        break;
    case SYS_FCHOWN:
        frame->x0 = 0;
        break;
    case SYS_FCHMOD:
        frame->x0 = 0;
        break;
    case SYS_UMASK:
        frame->x0 = 0;
        break;
    case SYS_SETPRIORITY:
        frame->x0 = 0;
        break;
    case SYS_MEMBARRIER:
        frame->x0 = 0;
        break;
    case SYS_SETSID:
        frame->x0 = 0;
        break;
    case SYS_SET_ROBUST_LIST:
        frame->x0 = 0;
        break;
    case SYS_RSEQ:
        frame->x0 = 0;
        break;
    case SYS_SCHED_GETAFFINITY:
        frame->x0 = 0;
        break;
    case SYS_GETRANDOM:
        void *buffer = (void *)arg1;
        size_t get_len = (size_t)arg2;
        uint32_t flags = (uint32_t)arg3;

        if (get_len == 0 || get_len > 1024 * 1024)
        {
            frame->x0 = (uint64_t)-EINVAL;
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

        frame->x0 = get_len;
        break;

    default:
        char buf[32];
        printk("syscall %d not implemented\n", idx);
        frame->x0 = (uint64_t)-ENOSYS;
        break;
    }
}
