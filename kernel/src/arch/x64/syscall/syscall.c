#include <arch/arch.h>
#include <task/task.h>
#include <task/futex.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/fcntl.h>
#include <mm/mm_syscall.h>
#include <net/net_syscall.h>
#include <libs/strerror.h>
#include <arch/x64/syscall/nr.h>

__attribute__((used, section(".limine_requests"))) volatile struct limine_date_at_boot_request boot_time_request =
    {
        .id = LIMINE_DATE_AT_BOOT_REQUEST,
        .revision = 0,
};

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
char sysname[] = "NeoAetherOS";
char nodename[] = "aether";
char release[] = BUILD_VERSION;
char version[] = BUILD_VERSION;
char machine[] = "x86_64";

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM];

uint64_t sys_getrandom(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    void *buffer = (void *)arg1;
    size_t get_len = (size_t)arg2;
    uint32_t flags = (uint32_t)arg3;

    if (get_len == 0 || get_len > 1024 * 1024)
    {
        return (uint64_t)-EINVAL;
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

    return get_len;
}

uint64_t sys_clock_gettime(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
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
        return 0;
    }
    case 7: // CLOCK_BOOTTIME
        if (arg2)
        {
            struct timespec *ts = (struct timespec *)arg2;
            ts->tv_sec = nanoTime() / 1000000000;
            ts->tv_nsec = nanoTime() % 1000000000;
        }
        return 0;
    case 0: // CLOCK_REALTIME
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
        return 0;
    }
    default:
        printk("clock not supported, clock_id = %d\n", arg1);
        return (uint64_t)-EINVAL;
    }
}

uint64_t sys_clock_getres(uint64_t arg1, uint64_t arg2)
{
    ((struct timespec *)arg2)->tv_sec = 0;
    ((struct timespec *)arg2)->tv_nsec = 1;
    return 0;
}

uint64_t sys_accept_normal(uint64_t arg1, struct sockaddr_un *arg2, socklen_t *arg3)
{
    return sys_accept(arg1, arg2, arg3, 0);
}

uint64_t sys_pipe_normal(uint64_t arg1)
{
    return sys_pipe((int *)arg1, 0);
}

uint64_t sys_gettimeofday(uint64_t arg1)
{
    tm time_day;
    time_read(&time_day);
    uint64_t timestamp_day = mktime(&time_day);
    if (arg1)
    {
        struct timespec *ts = (struct timespec *)arg1;
        ts->tv_sec = timestamp_day;
        ts->tv_nsec = 0;
    }
    return 0;
}

uint64_t sys_uname(uint64_t arg1)
{
    struct utsname *utsname = (struct utsname *)arg1;
    memcpy(utsname->sysname, sysname, sizeof(sysname));
    memcpy(utsname->nodename, nodename, sizeof(nodename));
    memcpy(utsname->release, release, sizeof(release));
    memcpy(utsname->version, version, sizeof(version));
    memcpy(utsname->machine, machine, sizeof(machine));
    return 0;
}

uint64_t sys_eventfd(uint64_t arg1)
{
    return sys_eventfd2(arg1, 0);
}

void syscall_handler_init()
{
    memset(syscall_handlers, 0, MAX_SYSCALL_NUM);

    syscall_handlers[SYS_READ] = (syscall_handle_t)sys_read;
    syscall_handlers[SYS_WRITE] = (syscall_handle_t)sys_write;
    syscall_handlers[SYS_OPEN] = (syscall_handle_t)sys_open;
    syscall_handlers[SYS_CLOSE] = (syscall_handle_t)sys_close;
    syscall_handlers[SYS_STAT] = (syscall_handle_t)sys_stat;
    syscall_handlers[SYS_FSTAT] = (syscall_handle_t)sys_fstat;
    syscall_handlers[SYS_LSTAT] = (syscall_handle_t)sys_stat;
    syscall_handlers[SYS_POLL] = (syscall_handle_t)sys_poll;
    syscall_handlers[SYS_LSEEK] = (syscall_handle_t)sys_lseek;
    syscall_handlers[SYS_MMAP] = (syscall_handle_t)sys_mmap;
    syscall_handlers[SYS_MPROTECT] = (syscall_handle_t)sys_mprotect;
    syscall_handlers[SYS_MUNMAP] = (syscall_handle_t)sys_munmap;
    // syscall_handlers[SYS_BRK] = (syscall_handle_t)sys_brk;
    syscall_handlers[SYS_RT_SIGACTION] = (syscall_handle_t)sys_sigaction;
    syscall_handlers[SYS_RT_SIGPROCMASK] = (syscall_handle_t)sys_ssetmask;
    syscall_handlers[SYS_RT_SIGRETURN] = (syscall_handle_t)sys_sigreturn;
    syscall_handlers[SYS_IOCTL] = (syscall_handle_t)sys_ioctl;
    syscall_handlers[SYS_PREAD64] = (syscall_handle_t)sys_pread64;
    syscall_handlers[SYS_PWRITE64] = (syscall_handle_t)sys_pwrite64;
    syscall_handlers[SYS_READV] = (syscall_handle_t)sys_readv;
    syscall_handlers[SYS_WRITEV] = (syscall_handle_t)sys_writev;
    syscall_handlers[SYS_ACCESS] = (syscall_handle_t)sys_access;
    syscall_handlers[SYS_PIPE] = (syscall_handle_t)sys_pipe_normal;
    syscall_handlers[SYS_SELECT] = (syscall_handle_t)sys_select;
    syscall_handlers[SYS_SCHED_YIELD] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_MREMAP] = (syscall_handle_t)sys_mremap;
    syscall_handlers[SYS_MSYNC] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_MINCORE] = (syscall_handle_t)sys_mincore;
    syscall_handlers[SYS_MADVISE] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SHMGET] = (syscall_handle_t)sys_shmget;
    syscall_handlers[SYS_SHMAT] = (syscall_handle_t)sys_shmat;
    syscall_handlers[SYS_SHMCTL] = (syscall_handle_t)sys_shmctl;
    syscall_handlers[SYS_DUP] = (syscall_handle_t)sys_dup;
    syscall_handlers[SYS_DUP2] = (syscall_handle_t)sys_dup2;
    syscall_handlers[SYS_PAUSE] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_NANOSLEEP] = (syscall_handle_t)sys_nanosleep;
    // syscall_handlers[SYS_GETITIMER] = (syscall_handle_t)sys_getitimer;
    // syscall_handlers[SYS_ALARM] = (syscall_handle_t)sys_alarm;
    syscall_handlers[SYS_SETITIMER] = (syscall_handle_t)sys_setitimer;
    syscall_handlers[SYS_GETPID] = (syscall_handle_t)sys_getpid;
    // syscall_handlers[SYS_SENDFILE] = (syscall_handle_t)sys_sendfile;
    syscall_handlers[SYS_SOCKET] = (syscall_handle_t)sys_socket;
    syscall_handlers[SYS_CONNECT] = (syscall_handle_t)sys_connect;
    syscall_handlers[SYS_ACCEPT] = (syscall_handle_t)sys_accept;
    syscall_handlers[SYS_SENDTO] = (syscall_handle_t)sys_send;
    syscall_handlers[SYS_RECVFROM] = (syscall_handle_t)sys_recv;
    syscall_handlers[SYS_SENDMSG] = (syscall_handle_t)sys_sendmsg;
    syscall_handlers[SYS_RECVMSG] = (syscall_handle_t)sys_recvmsg;
    syscall_handlers[SYS_SHUTDOWN] = (syscall_handle_t)sys_shutdown;
    syscall_handlers[SYS_BIND] = (syscall_handle_t)sys_bind;
    syscall_handlers[SYS_LISTEN] = (syscall_handle_t)sys_listen;
    syscall_handlers[SYS_GETSOCKNAME] = (syscall_handle_t)sys_getsockname;
    syscall_handlers[SYS_GETPEERNAME] = (syscall_handle_t)sys_getpeername;
    syscall_handlers[SYS_SOCKETPAIR] = (syscall_handle_t)sys_socketpair;
    syscall_handlers[SYS_SETSOCKOPT] = (syscall_handle_t)sys_setsockopt;
    syscall_handlers[SYS_GETSOCKOPT] = (syscall_handle_t)sys_getsockopt;
    syscall_handlers[SYS_CLONE] = (syscall_handle_t)sys_clone;
    syscall_handlers[SYS_FORK] = (syscall_handle_t)sys_fork;
    syscall_handlers[SYS_VFORK] = (syscall_handle_t)sys_vfork;
    syscall_handlers[SYS_EXECVE] = (syscall_handle_t)task_execve;
    syscall_handlers[SYS_EXIT] = (syscall_handle_t)task_exit;
    syscall_handlers[SYS_WAIT4] = (syscall_handle_t)sys_waitpid;
    syscall_handlers[SYS_KILL] = (syscall_handle_t)sys_kill;
    syscall_handlers[SYS_UNAME] = (syscall_handle_t)sys_uname;
    // syscall_handlers[SYS_SEMGET] = (syscall_handle_t)sys_semget;
    // syscall_handlers[SYS_SEMOP] = (syscall_handle_t)sys_semop;
    // syscall_handlers[SYS_SEMCTL] = (syscall_handle_t)sys_semctl;
    syscall_handlers[SYS_SHMDT] = (syscall_handle_t)sys_shmdt;
    // syscall_handlers[SYS_MSGGET] = (syscall_handle_t)sys_msgget;
    // syscall_handlers[SYS_MSGSND] = (syscall_handle_t)sys_msgsnd;
    // syscall_handlers[SYS_MSGRCV] = (syscall_handle_t)sys_msgrcv;
    // syscall_handlers[SYS_MSGCTL] = (syscall_handle_t)sys_msgctl;
    syscall_handlers[SYS_FCNTL] = (syscall_handle_t)sys_fcntl;
    syscall_handlers[SYS_FLOCK] = (syscall_handle_t)sys_flock;
    syscall_handlers[SYS_FSYNC] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_FDATASYNC] = (syscall_handle_t)sys_fdatasync;
    syscall_handlers[SYS_TRUNCATE] = (syscall_handle_t)sys_truncate;
    syscall_handlers[SYS_FTRUNCATE] = (syscall_handle_t)sys_ftruncate;
    syscall_handlers[SYS_GETDENTS] = (syscall_handle_t)sys_getdents;
    syscall_handlers[SYS_GETCWD] = (syscall_handle_t)sys_getcwd;
    syscall_handlers[SYS_CHDIR] = (syscall_handle_t)sys_chdir;
    syscall_handlers[SYS_FCHDIR] = (syscall_handle_t)sys_fchdir;
    syscall_handlers[SYS_RENAME] = (syscall_handle_t)sys_rename;
    syscall_handlers[SYS_MKDIR] = (syscall_handle_t)sys_mkdir;
    syscall_handlers[SYS_RMDIR] = (syscall_handle_t)sys_rmdir;
    // syscall_handlers[SYS_CREAT] = (syscall_handle_t)sys_creat;
    syscall_handlers[SYS_LINK] = (syscall_handle_t)sys_link;
    syscall_handlers[SYS_UNLINK] = (syscall_handle_t)sys_unlink;
    syscall_handlers[SYS_SYMLINK] = (syscall_handle_t)sys_symlink;
    syscall_handlers[SYS_READLINK] = (syscall_handle_t)sys_readlink;
    syscall_handlers[SYS_CHMOD] = (syscall_handle_t)sys_chmod;
    syscall_handlers[SYS_FCHMOD] = (syscall_handle_t)sys_fchmod;
    syscall_handlers[SYS_CHOWN] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_FCHOWN] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_LCHOWN] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_UMASK] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_GETTIMEOFDAY] = (syscall_handle_t)sys_gettimeofday;
    syscall_handlers[SYS_GETRLIMIT] = (syscall_handle_t)sys_get_rlimit;
    // syscall_handlers[SYS_GETRUSAGE] = (syscall_handle_t)sys_getrusage;
    syscall_handlers[SYS_SYSINFO] = (syscall_handle_t)sys_sysinfo;
    // syscall_handlers[SYS_TIMES] = (syscall_handle_t)sys_times;
    // syscall_handlers[SYS_PTRACE] = (syscall_handle_t)sys_ptrace;
    syscall_handlers[SYS_GETUID] = (syscall_handle_t)sys_getuid;
    syscall_handlers[SYS_SYSLOG] = (syscall_handle_t)sys_syslog;
    syscall_handlers[SYS_GETGID] = (syscall_handle_t)sys_getgid;
    syscall_handlers[SYS_SETUID] = (syscall_handle_t)sys_setuid;
    syscall_handlers[SYS_SETGID] = (syscall_handle_t)sys_setgid;
    syscall_handlers[SYS_GETEUID] = (syscall_handle_t)sys_geteuid;
    syscall_handlers[SYS_GETEGID] = (syscall_handle_t)sys_getegid;
    syscall_handlers[SYS_SETPGID] = (syscall_handle_t)sys_setpgid;
    syscall_handlers[SYS_GETPPID] = (syscall_handle_t)sys_getppid;
    // syscall_handlers[SYS_GETPGRP] = (syscall_handle_t)sys_getpgrp;
    syscall_handlers[SYS_SETSID] = (syscall_handle_t)sys_setsid;
    // syscall_handlers[SYS_SETREUID] = (syscall_handle_t)sys_setreuid;
    // syscall_handlers[SYS_SETREGID] = (syscall_handle_t)sys_setregid;
    syscall_handlers[SYS_GETGROUPS] = (syscall_handle_t)sys_getgroups;
    syscall_handlers[SYS_SETGROUPS] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SETRESUID] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_GETRESUID] = (syscall_handle_t)sys_getresuid;
    syscall_handlers[SYS_SETRESGID] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_GETRESGID] = (syscall_handle_t)sys_getresgid;
    syscall_handlers[SYS_GETPGID] = (syscall_handle_t)sys_getpgid;
    syscall_handlers[SYS_SETFSUID] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SETFSGID] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_GETSID] = (syscall_handle_t)sys_getsid;
    // syscall_handlers[SYS_CAPGET] = (syscall_handle_t)sys_capget;
    // syscall_handlers[SYS_CAPSET] = (syscall_handle_t)sys_capset;
    // syscall_handlers[SYS_RT_SIGPENDING] = (syscall_handle_t)sys_rt_sigpending;
    syscall_handlers[SYS_RT_SIGTIMEDWAIT] = (syscall_handle_t)sys_rt_sigtimedwait;
    // syscall_handlers[SYS_RT_SIGQUEUEINFO] = (syscall_handle_t)sys_rt_sigqueueinfo;
    // syscall_handlers[SYS_RT_SIGSUSPEND] = (syscall_handle_t)sys_sigsuspend;
    syscall_handlers[SYS_SIGALTSTACK] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_UTIME] = (syscall_handle_t)sys_utime;
    syscall_handlers[SYS_MKNOD] = (syscall_handle_t)sys_mknod;
    // syscall_handlers[SYS_USELIB] = (syscall_handle_t)sys_uselib;
    // syscall_handlers[SYS_PERSONALITY] = (syscall_handle_t)sys_personality;
    // syscall_handlers[SYS_USTAT] = (syscall_handle_t)sys_ustat;
    syscall_handlers[SYS_STATFS] = (syscall_handle_t)sys_statfs;
    syscall_handlers[SYS_FSTATFS] = (syscall_handle_t)sys_fstatfs;
    // syscall_handlers[SYS_SYSFS] = (syscall_handle_t)sys_sysfs;
    syscall_handlers[SYS_GETPRIORITY] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SETPRIORITY] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SCHED_SETPARAM] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SCHED_GETPARAM] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SCHED_SETSCHEDULER] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SCHED_GETSCHEDULER] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_SCHED_GET_PRIORITY_MAX] = (syscall_handle_t)sys_sched_get_priority_max;
    // syscall_handlers[SYS_SCHED_GET_PRIORITY_MIN] = (syscall_handle_t)sys_sched_get_priority_min;
    // syscall_handlers[SYS_SCHED_RR_GET_INTERVAL] = (syscall_handle_t)sys_sched_rr_get_interval;
    // syscall_handlers[SYS_MLOCK] = (syscall_handle_t)sys_mlock;
    // syscall_handlers[SYS_MUNLOCK] = (syscall_handle_t)sys_munlock;
    // syscall_handlers[SYS_MLOCKALL] = (syscall_handle_t)sys_mlockall;
    // syscall_handlers[SYS_MUNLOCKALL] = (syscall_handle_t)sys_munlockall;
    // syscall_handlers[SYS_VHANGUP] = (syscall_handle_t)sys_vhangup;
    // syscall_handlers[SYS_MODIFY_LDT] = (syscall_handle_t)sys_modify_ldt;
    // syscall_handlers[SYS_PIVOT_ROOT] = (syscall_handle_t)sys_pivot_root;
    // syscall_handlers[SYS__SYSCTL] = (syscall_handle_t)sys__sysctl;
    syscall_handlers[SYS_PRCTL] = (syscall_handle_t)sys_prctl;
    syscall_handlers[SYS_ARCH_PRCTL] = (syscall_handle_t)sys_arch_prctl;
    // syscall_handlers[SYS_ADJTIMEX] = (syscall_handle_t)sys_adjtimex;
    // syscall_handlers[SYS_SETRLIMIT] = (syscall_handle_t)sys_setrlimit;
    // syscall_handlers[SYS_CHROOT] = (syscall_handle_t)sys_chroot;
    // syscall_handlers[SYS_SYNC] = (syscall_handle_t)sys_sync;
    // syscall_handlers[SYS_ACCT] = (syscall_handle_t)sys_acct;
    // syscall_handlers[SYS_SETTIMEOFDAY] = (syscall_handle_t)sys_settimeofday;
    syscall_handlers[SYS_MOUNT] = (syscall_handle_t)sys_mount;
    // syscall_handlers[SYS_UMOUNT2] = (syscall_handle_t)sys_umount2;
    // syscall_handlers[SYS_SWAPON] = (syscall_handle_t)sys_swapon;
    // syscall_handlers[SYS_SWAPOFF] = (syscall_handle_t)sys_swapoff;
    syscall_handlers[SYS_REBOOT] = (syscall_handle_t)sys_reboot;
    // syscall_handlers[SYS_SETHOSTNAME] = (syscall_handle_t)sys_sethostname;
    // syscall_handlers[SYS_SETDOMAINNAME] = (syscall_handle_t)sys_setdomainname;
    // syscall_handlers[SYS_IOPL] = (syscall_handle_t)sys_iopl;
    // syscall_handlers[SYS_IOPERM] = (syscall_handle_t)sys_ioperm;
    // syscall_handlers[SYS_CREATE_MODULE] = (syscall_handle_t)sys_create_module;
    // syscall_handlers[SYS_INIT_MODULE] = (syscall_handle_t)sys_init_module;
    // syscall_handlers[SYS_DELETE_MODULE] = (syscall_handle_t)sys_delete_module;
    // syscall_handlers[SYS_GET_KERNEL_SYMS] = (syscall_handle_t)sys_get_kernel_syms;
    // syscall_handlers[SYS_QUERY_MODULE] = (syscall_handle_t)sys_query_module;
    // syscall_handlers[SYS_QUOTACTL] = (syscall_handle_t)sys_quotactl;
    // syscall_handlers[SYS_NFSSERVCTL] = (syscall_handle_t)sys_nfsservctl;
    // syscall_handlers[SYS_GETPMSG] = (syscall_handle_t)sys_getpmsg;
    // syscall_handlers[SYS_PUTPMSG] = (syscall_handle_t)sys_putpmsg;
    // syscall_handlers[SYS_AFS_SYSCALL] = (syscall_handle_t)sys_afs_syscall;
    // syscall_handlers[SYS_TUXCALL] = (syscall_handle_t)sys_tuxcall;
    // syscall_handlers[SYS_SECURITY] = (syscall_handle_t)sys_security;
    syscall_handlers[SYS_GETTID] = (syscall_handle_t)sys_getpid;
    // syscall_handlers[SYS_READAHEAD] = (syscall_handle_t)sys_readahead;
    // syscall_handlers[SYS_SETXATTR] = (syscall_handle_t)sys_setxattr;
    // syscall_handlers[SYS_LSETXATTR] = (syscall_handle_t)sys_lsetxattr;
    // syscall_handlers[SYS_FSETXATTR] = (syscall_handle_t)sys_fsetxattr;
    // syscall_handlers[SYS_GETXATTR] = (syscall_handle_t)sys_getxattr;
    // syscall_handlers[SYS_LGETXATTR] = (syscall_handle_t)sys_lgetxattr;
    // syscall_handlers[SYS_FGETXATTR] = (syscall_handle_t)sys_fgetxattr;
    // syscall_handlers[SYS_LISTXATTR] = (syscall_handle_t)sys_listxattr;
    // syscall_handlers[SYS_LLISTXATTR] = (syscall_handle_t)sys_llistxattr;
    // syscall_handlers[SYS_FLISTXATTR] = (syscall_handle_t)sys_flistxattr;
    // syscall_handlers[SYS_REMOVEXATTR] = (syscall_handle_t)sys_removexattr;
    // syscall_handlers[SYS_LREMOVEXATTR] = (syscall_handle_t)sys_lremovexattr;
    // syscall_handlers[SYS_FREMOVEXATTR] = (syscall_handle_t)sys_fremovexattr;
    // syscall_handlers[SYS_TKILL] = (syscall_handle_t)sys_kill;
    // syscall_handlers[SYS_TIME] = (syscall_handle_t)sys_time;
    syscall_handlers[SYS_FUTEX] = (syscall_handle_t)sys_futex;
    syscall_handlers[SYS_SCHED_SETAFFINITY] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_SCHED_GETAFFINITY] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_SET_THREAD_AREA] = (syscall_handle_t)sys_set_thread_area;
    // syscall_handlers[SYS_IO_SETUP] = (syscall_handle_t)sys_io_setup;
    // syscall_handlers[SYS_IO_DESTROY] = (syscall_handle_t)sys_io_destroy;
    // syscall_handlers[SYS_IO_GETEVENTS] = (syscall_handle_t)sys_io_getevents;
    // syscall_handlers[SYS_IO_SUBMIT] = (syscall_handle_t)sys_io_submit;
    // syscall_handlers[SYS_IO_CANCEL] = (syscall_handle_t)sys_io_cancel;
    // syscall_handlers[SYS_GET_THREAD_AREA] = (syscall_handle_t)sys_get_thread_area;
    // syscall_handlers[SYS_LOOKUP_DCOOKIE] = (syscall_handle_t)sys_lookup_dcookie;
    syscall_handlers[SYS_EPOLL_CREATE] = (syscall_handle_t)sys_epoll_create;
    // syscall_handlers[SYS_EPOLL_CTL_OLD] = (syscall_handle_t)sys_epoll_ctl_old;
    // syscall_handlers[SYS_EPOLL_WAIT_OLD] = (syscall_handle_t)sys_epoll_wait_old;
    // syscall_handlers[SYS_REMAP_FILE_PAGES] = (syscall_handle_t)sys_remap_file_pages;
    syscall_handlers[SYS_GETDENTS64] = (syscall_handle_t)sys_getdents;
    syscall_handlers[SYS_SET_TID_ADDRESS] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_RESTART_SYSCALL] = (syscall_handle_t)sys_restart_syscall;
    // syscall_handlers[SYS_SEMTIMEDOP] = (syscall_handle_t)sys_semtimedop;
    syscall_handlers[SYS_FADVISE64] = (syscall_handle_t)dummy_syscall_handler;
    syscall_handlers[SYS_TIMER_CREATE] = (syscall_handle_t)sys_timer_create;
    syscall_handlers[SYS_TIMER_SETTIME] = (syscall_handle_t)sys_timer_settime;
    // syscall_handlers[SYS_TIMER_GETTIME] = (syscall_handle_t)sys_timer_gettime;
    // syscall_handlers[SYS_TIMER_GETOVERRUN] = (syscall_handle_t)sys_timer_getoverrun;
    // syscall_handlers[SYS_TIMER_DELETE] = (syscall_handle_t)sys_timer_delete;
    // syscall_handlers[SYS_CLOCK_SETTIME] = (syscall_handle_t)sys_clock_settime;
    syscall_handlers[SYS_CLOCK_GETTIME] = (syscall_handle_t)sys_clock_gettime;
    syscall_handlers[SYS_CLOCK_GETRES] = (syscall_handle_t)sys_clock_getres;
    // syscall_handlers[SYS_CLOCK_NANOSLEEP] = (syscall_handle_t)sys_clock_nanosleep;
    syscall_handlers[SYS_EXIT_GROUP] = (syscall_handle_t)task_exit;
    syscall_handlers[SYS_EPOLL_WAIT] = (syscall_handle_t)sys_epoll_wait;
    syscall_handlers[SYS_EPOLL_CTL] = (syscall_handle_t)sys_epoll_ctl;
    // syscall_handlers[SYS_TGKILL] = (syscall_handle_t)sys_tgkill;
    // syscall_handlers[SYS_UTIMES] = (syscall_handle_t)sys_utimes;
    // syscall_handlers[SYS_VSERVER] = (syscall_handle_t)sys_vserver;
    // syscall_handlers[SYS_MBIND] = (syscall_handle_t)sys_mbind;
    // syscall_handlers[SYS_SET_MEMPOLICY] = (syscall_handle_t)sys_set_mempolicy;
    // syscall_handlers[SYS_GET_MEMPOLICY] = (syscall_handle_t)sys_get_mempolicy;
    // syscall_handlers[SYS_MQ_OPEN] = (syscall_handle_t)sys_mq_open;
    // syscall_handlers[SYS_MQ_UNLINK] = (syscall_handle_t)sys_mq_unlink;
    // syscall_handlers[SYS_MQ_TIMEDSEND] = (syscall_handle_t)sys_mq_timedsend;
    // syscall_handlers[SYS_MQ_TIMEDRECEIVE] = (syscall_handle_t)sys_mq_timedreceive;
    // syscall_handlers[SYS_MQ_NOTIFY] = (syscall_handle_t)sys_mq_notify;
    // syscall_handlers[SYS_MQ_GETSETATTR] = (syscall_handle_t)sys_mq_getsetattr;
    // syscall_handlers[SYS_KEXEC_LOAD] = (syscall_handle_t)sys_kexec_load;
    // syscall_handlers[SYS_WAITID] = (syscall_handle_t)sys_waitid;
    // syscall_handlers[SYS_ADD_KEY] = (syscall_handle_t)sys_add_key;
    // syscall_handlers[SYS_REQUEST_KEY] = (syscall_handle_t)sys_request_key;
    // syscall_handlers[SYS_KEYCTL] = (syscall_handle_t)sys_keyctl;
    // syscall_handlers[SYS_IOPRIO_SET] = (syscall_handle_t)sys_ioprio_set;
    // syscall_handlers[SYS_IOPRIO_GET] = (syscall_handle_t)sys_ioprio_get;
    // syscall_handlers[SYS_INOTIFY_INIT] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_INOTIFY_ADD_WATCH] = (syscall_handle_t)sys_inotify_add_watch;
    // syscall_handlers[SYS_INOTIFY_RM_WATCH] = (syscall_handle_t)sys_inotify_rm_watch;
    // syscall_handlers[SYS_MIGRATE_PAGES] = (syscall_handle_t)sys_migrate_pages;
    syscall_handlers[SYS_OPENAT] = (syscall_handle_t)sys_openat;
    syscall_handlers[SYS_MKDIRAT] = (syscall_handle_t)sys_mkdirat;
    // syscall_handlers[SYS_MKNODAT] = (syscall_handle_t)sys_mknodat;
    // syscall_handlers[SYS_FCHOWNAT] = (syscall_handle_t)sys_fchownat;
    syscall_handlers[SYS_FUTIMESAT] = (syscall_handle_t)sys_futimesat;
    syscall_handlers[SYS_NEWFSTATAT] = (syscall_handle_t)sys_newfstatat;
    syscall_handlers[SYS_UNLINKAT] = (syscall_handle_t)sys_unlinkat;
    syscall_handlers[SYS_RENAMEAT] = (syscall_handle_t)sys_renameat;
    // syscall_handlers[SYS_LINKAT] = (syscall_handle_t)sys_linkat;
    syscall_handlers[SYS_SYMLINKAT] = (syscall_handle_t)sys_symlinkat;
    syscall_handlers[SYS_READLINKAT] = (syscall_handle_t)sys_readlinkat;
    syscall_handlers[SYS_FCHMODAT] = (syscall_handle_t)sys_fchmodat;
    syscall_handlers[SYS_FACCESSAT] = (syscall_handle_t)sys_faccessat;
    syscall_handlers[SYS_PSELECT6] = (syscall_handle_t)sys_pselect6;
    syscall_handlers[SYS_PPOLL] = (syscall_handle_t)sys_ppoll;
    // syscall_handlers[SYS_UNSHARE] = (syscall_handle_t)sys_unshare;
    syscall_handlers[SYS_SET_ROBUST_LIST] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_GET_ROBUST_LIST] = (syscall_handle_t)sys_get_robust_list;
    // syscall_handlers[SYS_SPLICE] = (syscall_handle_t)sys_splice;
    // syscall_handlers[SYS_TEE] = (syscall_handle_t)sys_tee;
    // syscall_handlers[SYS_SYNC_FILE_RANGE] = (syscall_handle_t)sys_sync_file_range;
    // syscall_handlers[SYS_VMSPLICE] = (syscall_handle_t)sys_vmsplice;
    // syscall_handlers[SYS_MOVE_PAGES] = (syscall_handle_t)sys_move_pages;
    syscall_handlers[SYS_UTIMENSAT] = (syscall_handle_t)sys_utimensat;
    syscall_handlers[SYS_EPOLL_PWAIT] = (syscall_handle_t)sys_epoll_pwait;
    syscall_handlers[SYS_SIGNALFD] = (syscall_handle_t)sys_signalfd;
    syscall_handlers[SYS_TIMERFD_CREATE] = (syscall_handle_t)sys_timerfd_create;
    syscall_handlers[SYS_EVENTFD] = (syscall_handle_t)sys_eventfd;
    syscall_handlers[SYS_FALLOCATE] = (syscall_handle_t)sys_fallocate;
    syscall_handlers[SYS_TIMERFD_SETTIME] = (syscall_handle_t)sys_timerfd_settime;
    // syscall_handlers[SYS_TIMERFD_GETTIME] = (syscall_handle_t)sys_timerfd_gettime;
    syscall_handlers[SYS_ACCEPT4] = (syscall_handle_t)sys_accept;
    syscall_handlers[SYS_SIGNALFD4] = (syscall_handle_t)sys_signalfd4;
    syscall_handlers[SYS_EVENTFD2] = (syscall_handle_t)sys_eventfd2;
    syscall_handlers[SYS_EPOLL_CREATE1] = (syscall_handle_t)sys_epoll_create1;
    syscall_handlers[SYS_DUP3] = (syscall_handle_t)sys_dup3;
    syscall_handlers[SYS_PIPE2] = (syscall_handle_t)sys_pipe;
    syscall_handlers[SYS_INOTIFY_INIT1] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_PREADV] = (syscall_handle_t)sys_preadv;
    // syscall_handlers[SYS_PWRITEV] = (syscall_handle_t)sys_pwritev;
    // syscall_handlers[SYS_RT_TGSIGQUEUEINFO] = (syscall_handle_t)sys_rt_tgsigqueueinfo;
    // syscall_handlers[SYS_PERF_EVENT_OPEN] = (syscall_handle_t)sys_perf_event_open;
    // syscall_handlers[SYS_RECVMMSG] = (syscall_handle_t)sys_recvmmsg;
    // syscall_handlers[SYS_FANOTIFY_INIT] = (syscall_handle_t)sys_fanotify_init;
    // syscall_handlers[SYS_FANOTIFY_MARK] = (syscall_handle_t)sys_fanotify_mark;
    syscall_handlers[SYS_PRLIMIT64] = (syscall_handle_t)sys_prlimit64;
    // syscall_handlers[SYS_NAME_TO_HANDLE_AT] = (syscall_handle_t)sys_name_to_handle_at;
    // syscall_handlers[SYS_OPEN_BY_HANDLE_AT] = (syscall_handle_t)sys_open_by_handle_at;
    // syscall_handlers[SYS_CLOCK_ADJTIME] = (syscall_handle_t)sys_clock_adjtime;
    // syscall_handlers[SYS_SYNCFS] = (syscall_handle_t)sys_syncfs;
    // syscall_handlers[SYS_SENDMMSG] = (syscall_handle_t)sys_sendmmsg;
    // syscall_handlers[SYS_SETNS] = (syscall_handle_t)sys_setns;
    // syscall_handlers[SYS_GETCPU] = (syscall_handle_t)sys_getcpu;
    // syscall_handlers[SYS_PROCESS_VM_READV] = (syscall_handle_t)sys_process_vm_readv;
    // syscall_handlers[SYS_PROCESS_VM_WRITEV] = (syscall_handle_t)sys_process_vm_writev;
    // syscall_handlers[SYS_KCMP] = (syscall_handle_t)sys_kcmp;
    // syscall_handlers[SYS_FINIT_MODULE] = (syscall_handle_t)sys_finit_module;
    // syscall_handlers[SYS_SCHED_SETATTR] = (syscall_handle_t)sys_sched_setattr;
    // syscall_handlers[SYS_SCHED_GETATTR] = (syscall_handle_t)sys_sched_getattr;
    // syscall_handlers[SYS_RENAMEAT2] = (syscall_handle_t)sys_renameat2;
    // syscall_handlers[SYS_SECCOMP] = (syscall_handle_t)sys_seccomp;
    syscall_handlers[SYS_GETRANDOM] = (syscall_handle_t)sys_getrandom;
    syscall_handlers[SYS_MEMFD_CREATE] = (syscall_handle_t)sys_memfd_create;
    // syscall_handlers[SYS_KEXEC_FILE_LOAD] = (syscall_handle_t)sys_kexec_file_load;
    // syscall_handlers[SYS_BPF] = (syscall_handle_t)sys_bpf;
    // syscall_handlers[SYS_EXECVEAT] = (syscall_handle_t)sys_execveat;
    // syscall_handlers[SYS_USERFAULTFD] = (syscall_handle_t)sys_userfaultfd;
    syscall_handlers[SYS_MEMBARRIER] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_MLOCK2] = (syscall_handle_t)sys_mlock2;
    syscall_handlers[SYS_COPY_FILE_RANGE] = (syscall_handle_t)sys_copy_file_range;
    // syscall_handlers[SYS_PREADV2] = (syscall_handle_t)sys_preadv2;
    // syscall_handlers[SYS_PWRITEV2] = (syscall_handle_t)sys_pwritev2;
    // syscall_handlers[SYS_PKEY_MPROTECT] = (syscall_handle_t)sys_pkey_mprotect;
    // syscall_handlers[SYS_PKEY_ALLOC] = (syscall_handle_t)sys_pkey_alloc;
    // syscall_handlers[SYS_PKEY_FREE] = (syscall_handle_t)sys_pkey_free;
    syscall_handlers[SYS_STATX] = (syscall_handle_t)sys_statx;
    // syscall_handlers[SYS_IO_PGETEVENTS] = (syscall_handle_t)sys_io_pgetevents;
    syscall_handlers[SYS_RSEQ] = (syscall_handle_t)dummy_syscall_handler;
    // syscall_handlers[SYS_PIDFD_SEND_SIGNAL] = (syscall_handle_t)sys_pidfd_send_signal;
    // syscall_handlers[SYS_IO_URING_SETUP] = (syscall_handle_t)sys_io_uring_setup;
    // syscall_handlers[SYS_IO_URING_ENTER] = (syscall_handle_t)sys_io_uring_enter;
    // syscall_handlers[SYS_IO_URING_REGISTER] = (syscall_handle_t)sys_io_uring_register;
    // syscall_handlers[SYS_OPEN_TREE] = (syscall_handle_t)sys_open_tree;
    // syscall_handlers[SYS_MOVE_MOUNT] = (syscall_handle_t)sys_move_mount;
    syscall_handlers[SYS_FSOPEN] = (syscall_handle_t)sys_fsopen;
    // syscall_handlers[SYS_FSCONFIG] = (syscall_handle_t)sys_fsconfig;
    // syscall_handlers[SYS_FSMOUNT] = (syscall_handle_t)sys_fsmount;
    // syscall_handlers[SYS_FSPICK] = (syscall_handle_t)sys_fspick;
    // syscall_handlers[SYS_PIDFD_OPEN] = (syscall_handle_t)sys_pidfd_open;
    // syscall_handlers[SYS_CLONE3] = (syscall_handle_t)sys_clone3;
    syscall_handlers[SYS_CLOSE_RANGE] = (syscall_handle_t)sys_close_range;
    // syscall_handlers[SYS_OPENAT2] = (syscall_handle_t)sys_openat2;
    // syscall_handlers[SYS_PIDFD_GETFD] = (syscall_handle_t)sys_pidfd_getfd;
    syscall_handlers[SYS_FACCESSAT2] = (syscall_handle_t)sys_faccessat2;
    // syscall_handlers[SYS_PROCESS_MADVISE] = (syscall_handle_t)sys_process_madvise;
    // syscall_handlers[SYS_EPOLL_PWAIT2] = (syscall_handle_t)sys_epoll_pwait2;
    // syscall_handlers[SYS_MOUNT_SETATTR] = (syscall_handle_t)sys_mount_setattr;
    // syscall_handlers[SYS_LANDLOCK_CREATE_RULESET] = (syscall_handle_t)sys_landlock_create_ruleset;
    // syscall_handlers[SYS_LANDLOCK_ADD_RULE] = (syscall_handle_t)sys_landlock_add_rule;
    // syscall_handlers[SYS_LANDLOCK_RESTRICT_SELF] = (syscall_handle_t)sys_landlock_restrict_self;
    // syscall_handlers[SYS_MEMFD_SECRET] = (syscall_handle_t)sys_memfd_secret;
    // syscall_handlers[SYS_PROCESS_MRELEASE] = (syscall_handle_t)sys_process_mrelease;
    // syscall_handlers[SYS_FUTEX_WAITV] = (syscall_handle_t)sys_futex_waitv;
    // syscall_handlers[SYS_SET_MEMPOLICY_HOME_NODE] = (syscall_handle_t)sys_set_mempolicy_home_node;
    // syscall_handlers[SYS_CACHESTAT] = (syscall_handle_t)sys_cachestat;
    // syscall_handlers[SYS_FCHMODAT2] = (syscall_handle_t)sys_fchmodat2;
}

spinlock_t syscall_debug_lock = {0};

void syscall_handler(struct pt_regs *regs, uint64_t user_regs)
{
    regs->rip = regs->rcx;
    regs->rflags = regs->r11;
    regs->cs = SELECTOR_USER_CS;
    regs->ss = SELECTOR_USER_DS;
    regs->ds = SELECTOR_USER_DS;
    regs->es = SELECTOR_USER_DS;
    regs->rsp = user_regs;

    uint64_t idx = regs->rax & 0xFFFFFFFF;

    uint64_t arg1 = regs->rdi;
    uint64_t arg2 = regs->rsi;
    uint64_t arg3 = regs->rdx;
    uint64_t arg4 = regs->r10;
    uint64_t arg5 = regs->r8;
    uint64_t arg6 = regs->r9;

    if (idx > MAX_SYSCALL_NUM)
    {
        regs->rax = (uint64_t)-ENOSYS;
        goto done;
    }

    syscall_handle_t handler = syscall_handlers[idx];
    if (!handler)
    {
        regs->rax = (uint64_t)-ENOSYS;
        goto done;
    }

    if (idx == SYS_FORK || idx == SYS_VFORK || idx == SYS_CLONE || idx == SYS_CLONE3 || idx == SYS_RT_SIGRETURN)
    {
        special_syscall_handle_t h = (special_syscall_handle_t)handler;
        regs->rax = h(regs, arg1, arg2, arg3, arg4, arg5, arg6);
    }
    else
    {
        regs->rax = handler(arg1, arg2, arg3, arg4, arg5, arg6);
    }

    if ((idx != SYS_BRK) && (idx != SYS_MMAP) && (idx != SYS_MREMAP) && (idx != SYS_SHMAT) && (idx != SYS_FCNTL) && (int)regs->rax < 0 && !((int64_t)regs->rax < 0))
        regs->rax |= 0xffffffff00000000;
    if ((int)regs->rax == 0 && (int64_t)regs->rax < 0)
        regs->rax = 0;

    // if ((int64_t)regs->rax < 0)
    // {
    //     char buf[128];
    //     int len = sprintf(buf, "syscall %d has error: %s\n", idx, strerror(-(int)regs->rax));
    //     serial_printk(buf, len);
    // }

    bool usable = idx < (sizeof(linux_syscalls) / sizeof(linux_syscalls[0]));
    const LINUX_SYSCALL *info = &linux_syscalls[idx];

    char buf[256];
    int len;

#define SYSCALL_DEBUG 0
#if SYSCALL_DEBUG
    spin_lock(&syscall_debug_lock);

    len = sprintf(buf, "%d [syscall] %s(", current_task->pid, usable ? info->name : "???");
    serial_printk(buf, len);
    if (usable)
    {
        if (info->arg1[0])
        {
            len = sprintf(buf, "%s:%lx,", info->arg1, arg1);
            serial_printk(buf, len);
        }
        if (info->arg2[0])
        {
            len = sprintf(buf, "%s:%lx,", info->arg2, arg2);
            serial_printk(buf, len);
        }
        if (info->arg3[0])
        {
            len = sprintf(buf, "%s:%lx,", info->arg3, arg3);
            serial_printk(buf, len);
        }
        if (info->arg4[0])
        {
            len = sprintf(buf, "%s:%lx,", info->arg4, arg4);
            serial_printk(buf, len);
        }
        if (info->arg5[0])
        {
            len = sprintf(buf, "%s:%lx,", info->arg5, arg5);
            serial_printk(buf, len);
        }
        if (info->arg6[0])
        {
            len = sprintf(buf, "%s:%lx,", info->arg6, arg6);
            serial_printk(buf, len);
        }
    }
    if ((int64_t)regs->rax < 0)
    {
        len = sprintf(buf, "\b) = %s%s%s\n", "ERR(", strerror(-regs->rax), ")");
    }
    else
    {
        len = sprintf(buf, "\b) = %d\n", regs->rax);
    }
    serial_printk(buf, len);

    spin_unlock(&syscall_debug_lock);
#endif

done:
    if (idx != SYS_BRK && regs->rax == (uint64_t)-ENOSYS)
    {
        char buf[32];
        int len = sprintf(buf, "syscall %d not implemented\n", idx);
        serial_printk(buf, len);
    }
}
