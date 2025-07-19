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

    syscall_handlers_init();
}

syscall_handler_t syscall_handlers[NR_SYSCALL] = {0};

void syscall_handlers_init()
{
    memset(syscall_handlers, 0, sizeof(syscall_handlers));

    syscall_handlers[SYS_READ] = (syscall_handler_t)sys_read;
    syscall_handlers[SYS_WRITE] = (syscall_handler_t)sys_write;
    syscall_handlers[SYS_OPEN] = (syscall_handler_t)sys_open;
    syscall_handlers[SYS_CLOSE] = (syscall_handler_t)sys_close;
    syscall_handlers[SYS_STAT] = (syscall_handler_t)sys_stat;
    syscall_handlers[SYS_FSTAT] = (syscall_handler_t)sys_fstat;
    syscall_handlers[SYS_LSTAT] = (syscall_handler_t)sys_stat;
    syscall_handlers[SYS_POLL] = (syscall_handler_t)sys_poll;
    syscall_handlers[SYS_LSEEK] = (syscall_handler_t)sys_lseek;
    syscall_handlers[SYS_MMAP] = (syscall_handler_t)sys_mmap;
    syscall_handlers[SYS_MPROTECT] = (syscall_handler_t)sys_mprotect;
    syscall_handlers[SYS_MUNMAP] = (syscall_handler_t)sys_munmap;
    syscall_handlers[SYS_BRK] = (syscall_handler_t)sys_brk;
    syscall_handlers[SYS_RT_SIGACTION] = (syscall_handler_t)sys_sigaction;
    syscall_handlers[SYS_RT_SIGPROCMASK] = (syscall_handler_t)sys_ssetmask;
    syscall_handlers[SYS_RT_SIGRETURN] = (syscall_handler_t)sys_sigreturn;
    syscall_handlers[SYS_IOCTL] = (syscall_handler_t)sys_ioctl;
    syscall_handlers[SYS_PREAD64] = (syscall_handler_t)sys_pread64;
    syscall_handlers[SYS_PWRITE64] = (syscall_handler_t)sys_pwrite64;
    syscall_handlers[SYS_READV] = (syscall_handler_t)sys_readv;
    syscall_handlers[SYS_WRITEV] = (syscall_handler_t)sys_writev;
    syscall_handlers[SYS_ACCESS] = (syscall_handler_t)sys_access;
    syscall_handlers[SYS_PIPE] = (syscall_handler_t)sys_pipe_normal;
    syscall_handlers[SYS_SELECT] = (syscall_handler_t)sys_select;
    // syscall_handlers[SYS_SCHED_YIELD] = (syscall_handler_t)sys_sched_yield;
    syscall_handlers[SYS_MREMAP] = (syscall_handler_t)sys_mremap;
    // syscall_handlers[SYS_MSYNC] = (syscall_handler_t)sys_msync;
    syscall_handlers[SYS_MINCORE] = (syscall_handler_t)sys_mincore;
    // syscall_handlers[SYS_MADVISE] = (syscall_handler_t)sys_madvise;
    // syscall_handlers[SYS_SHMGET] = (syscall_handler_t)sys_shmget;
    // syscall_handlers[SYS_SHMAT] = (syscall_handler_t)sys_shmat;
    // syscall_handlers[SYS_SHMCTL] = (syscall_handler_t)sys_shmctl;
    syscall_handlers[SYS_DUP] = (syscall_handler_t)sys_dup;
    syscall_handlers[SYS_DUP2] = (syscall_handler_t)sys_dup2;
    // syscall_handlers[SYS_PAUSE] = (syscall_handler_t)sys_pause;
    syscall_handlers[SYS_NANOSLEEP] = (syscall_handler_t)sys_nanosleep;
    // syscall_handlers[SYS_GETITIMER] = (syscall_handler_t)sys_getitimer;
    // syscall_handlers[SYS_ALARM] = (syscall_handler_t)sys_alarm;
    syscall_handlers[SYS_SETITIMER] = (syscall_handler_t)sys_setitimer;
    syscall_handlers[SYS_GETPID] = (syscall_handler_t)sys_getpid;
    // syscall_handlers[SYS_SENDFILE] = (syscall_handler_t)sys_sendfile;
    syscall_handlers[SYS_SOCKET] = (syscall_handler_t)sys_socket;
    syscall_handlers[SYS_CONNECT] = (syscall_handler_t)sys_connect;
    syscall_handlers[SYS_ACCEPT] = (syscall_handler_t)sys_accept_normal;
    syscall_handlers[SYS_SENDTO] = (syscall_handler_t)sys_send;
    syscall_handlers[SYS_RECVFROM] = (syscall_handler_t)sys_recv;
    syscall_handlers[SYS_SENDMSG] = (syscall_handler_t)sys_sendmsg;
    syscall_handlers[SYS_RECVMSG] = (syscall_handler_t)sys_recvmsg;
    syscall_handlers[SYS_SHUTDOWN] = (syscall_handler_t)sys_shutdown;
    syscall_handlers[SYS_BIND] = (syscall_handler_t)sys_bind;
    syscall_handlers[SYS_LISTEN] = (syscall_handler_t)sys_listen;
    syscall_handlers[SYS_GETSOCKNAME] = (syscall_handler_t)sys_getsockname;
    syscall_handlers[SYS_GETPEERNAME] = (syscall_handler_t)sys_getpeername;
    syscall_handlers[SYS_SOCKETPAIR] = (syscall_handler_t)sys_socketpair;
    syscall_handlers[SYS_SETSOCKOPT] = (syscall_handler_t)sys_setsockopt;
    syscall_handlers[SYS_GETSOCKOPT] = (syscall_handler_t)sys_getsockopt;
    syscall_handlers[SYS_CLONE] = (syscall_handler_t)sys_clone;
    syscall_handlers[SYS_FORK] = (syscall_handler_t)sys_fork;
    syscall_handlers[SYS_VFORK] = (syscall_handler_t)sys_vfork;
    syscall_handlers[SYS_EXECVE] = (syscall_handler_t)task_execve;
    syscall_handlers[SYS_EXIT] = (syscall_handler_t)task_exit;
    syscall_handlers[SYS_WAIT4] = (syscall_handler_t)sys_waitpid;
    syscall_handlers[SYS_KILL] = (syscall_handler_t)sys_kill;
    syscall_handlers[SYS_UNAME] = (syscall_handler_t)sys_uname;
    // syscall_handlers[SYS_SEMGET] = (syscall_handler_t)sys_semget;
    // syscall_handlers[SYS_SEMOP] = (syscall_handler_t)sys_semop;
    // syscall_handlers[SYS_SEMCTL] = (syscall_handler_t)sys_semctl;
    // syscall_handlers[SYS_SHMDT] = (syscall_handler_t)sys_shmdt;
    // syscall_handlers[SYS_MSGGET] = (syscall_handler_t)sys_msgget;
    // syscall_handlers[SYS_MSGSND] = (syscall_handler_t)sys_msgsnd;
    // syscall_handlers[SYS_MSGRCV] = (syscall_handler_t)sys_msgrcv;
    // syscall_handlers[SYS_MSGCTL] = (syscall_handler_t)sys_msgctl;
    syscall_handlers[SYS_FCNTL] = (syscall_handler_t)sys_fcntl;
    syscall_handlers[SYS_FLOCK] = (syscall_handler_t)sys_flock;
    // syscall_handlers[SYS_FSYNC] = (syscall_handler_t)sys_fsync;
    // syscall_handlers[SYS_FDATASYNC] = (syscall_handler_t)sys_fdatasync;
    syscall_handlers[SYS_TRUNCATE] = (syscall_handler_t)syscall_dummy_handler;
    syscall_handlers[SYS_FTRUNCATE] = (syscall_handler_t)syscall_dummy_handler;
    syscall_handlers[SYS_GETDENTS] = (syscall_handler_t)sys_getdents;
    syscall_handlers[SYS_GETCWD] = (syscall_handler_t)sys_getcwd;
    syscall_handlers[SYS_CHDIR] = (syscall_handler_t)sys_chdir;
    syscall_handlers[SYS_FCHDIR] = (syscall_handler_t)sys_fchdir;
    syscall_handlers[SYS_RENAME] = (syscall_handler_t)sys_rename;
    syscall_handlers[SYS_MKDIR] = (syscall_handler_t)sys_mkdir;
    syscall_handlers[SYS_RMDIR] = (syscall_handler_t)sys_rmdir;
    // syscall_handlers[SYS_CREAT] = (syscall_handler_t)sys_creat;
    syscall_handlers[SYS_LINK] = (syscall_handler_t)sys_link;
    syscall_handlers[SYS_UNLINK] = (syscall_handler_t)sys_unlink;
    syscall_handlers[SYS_SYMLINK] = (syscall_handler_t)sys_symlink;
    syscall_handlers[SYS_READLINK] = (syscall_handler_t)sys_readlink;
    syscall_handlers[SYS_CHMOD] = (syscall_handler_t)sys_chmod;
    syscall_handlers[SYS_FCHMOD] = (syscall_handler_t)sys_fchmod;
    // syscall_handlers[SYS_CHOWN] = (syscall_handler_t)sys_chown;
    // syscall_handlers[SYS_FCHOWN] = (syscall_handler_t)sys_fchown;
    // syscall_handlers[SYS_LCHOWN] = (syscall_handler_t)sys_lchown;
    syscall_handlers[SYS_UMASK] = (syscall_handler_t)sys_umask;
    // syscall_handlers[SYS_GETTIMEOFDAY] = (syscall_handler_t)sys_gettimeofday;
    syscall_handlers[SYS_GETRLIMIT] = (syscall_handler_t)sys_get_rlimit;
    syscall_handlers[SYS_GETRUSAGE] = (syscall_handler_t)syscall_dummy_handler;
    syscall_handlers[SYS_SYSINFO] = (syscall_handler_t)syscall_dummy_handler;
    // syscall_handlers[SYS_TIMES] = (syscall_handler_t)sys_times;
    // syscall_handlers[SYS_PTRACE] = (syscall_handler_t)sys_ptrace;
    syscall_handlers[SYS_GETUID] = (syscall_handler_t)sys_getuid;
    // syscall_handlers[SYS_SYSLOG] = (syscall_handler_t)sys_syslog;
    syscall_handlers[SYS_GETGID] = (syscall_handler_t)sys_getgid;
    syscall_handlers[SYS_SETUID] = (syscall_handler_t)sys_setuid;
    syscall_handlers[SYS_SETGID] = (syscall_handler_t)sys_setgid;
    syscall_handlers[SYS_GETEUID] = (syscall_handler_t)sys_geteuid;
    syscall_handlers[SYS_GETEGID] = (syscall_handler_t)sys_getegid;
    syscall_handlers[SYS_SETPGID] = (syscall_handler_t)sys_setpgid;
    syscall_handlers[SYS_GETPPID] = (syscall_handler_t)sys_getppid;
    // syscall_handlers[SYS_GETPGRP] = (syscall_handler_t)sys_getpgrp;
    syscall_handlers[SYS_SETSID] = (syscall_handler_t)sys_setsid;
    // syscall_handlers[SYS_SETREUID] = (syscall_handler_t)sys_setreuid;
    // syscall_handlers[SYS_SETREGID] = (syscall_handler_t)sys_setregid;
    // syscall_handlers[SYS_GETGROUPS] = (syscall_handler_t)sys_getgroups;
    // syscall_handlers[SYS_SETGROUPS] = (syscall_handler_t)sys_setgroups;
    syscall_handlers[SYS_SETRESUID] = (syscall_handler_t)sys_setruid;
    syscall_handlers[SYS_GETRESUID] = (syscall_handler_t)sys_getruid;
    syscall_handlers[SYS_SETRESGID] = (syscall_handler_t)sys_setrgid;
    syscall_handlers[SYS_GETRESGID] = (syscall_handler_t)sys_getrgid;
    syscall_handlers[SYS_GETPGID] = (syscall_handler_t)sys_getpgid;
    syscall_handlers[SYS_SETFSUID] = (syscall_handler_t)sys_setfsuid;
    syscall_handlers[SYS_SETFSGID] = (syscall_handler_t)sys_setfsgid;
    syscall_handlers[SYS_GETSID] = (syscall_handler_t)sys_getsid;
    // syscall_handlers[SYS_CAPGET] = (syscall_handler_t)sys_capget;
    // syscall_handlers[SYS_CAPSET] = (syscall_handler_t)sys_capset;
    // syscall_handlers[SYS_RT_SIGPENDING] = (syscall_handler_t)sys_rt_sigpending;
    // syscall_handlers[SYS_RT_SIGTIMEDWAIT] = (syscall_handler_t)sys_rt_sigtimedwait;
    // syscall_handlers[SYS_RT_SIGQUEUEINFO] = (syscall_handler_t)sys_rt_sigqueueinfo;
    syscall_handlers[SYS_RT_SIGSUSPEND] = (syscall_handler_t)sys_sigsuspend;
    // syscall_handlers[SYS_SIGALTSTACK] = (syscall_handler_t)sys_sigaltstack;
    // syscall_handlers[SYS_UTIME] = (syscall_handler_t)sys_utime;
    // syscall_handlers[SYS_MKNOD] = (syscall_handler_t)sys_mknod;
    // syscall_handlers[SYS_USELIB] = (syscall_handler_t)sys_uselib;
    // syscall_handlers[SYS_PERSONALITY] = (syscall_handler_t)sys_personality;
    // syscall_handlers[SYS_USTAT] = (syscall_handler_t)sys_ustat;
    syscall_handlers[SYS_STATFS] = (syscall_handler_t)syscall_dummy_handler;
    syscall_handlers[SYS_FSTATFS] = (syscall_handler_t)syscall_dummy_handler;
    // syscall_handlers[SYS_SYSFS] = (syscall_handler_t)sys_sysfs;
    syscall_handlers[SYS_GETPRIORITY] = (syscall_handler_t)syscall_dummy_handler;
    syscall_handlers[SYS_SETPRIORITY] = (syscall_handler_t)syscall_dummy_handler;
    // syscall_handlers[SYS_SCHED_SETPARAM] = (syscall_handler_t)sys_sched_setparam;
    // syscall_handlers[SYS_SCHED_GETPARAM] = (syscall_handler_t)sys_sched_getparam;
    // syscall_handlers[SYS_SCHED_SETSCHEDULER] = (syscall_handler_t)sys_sched_setscheduler;
    // syscall_handlers[SYS_SCHED_GETSCHEDULER] = (syscall_handler_t)sys_sched_getscheduler;
    // syscall_handlers[SYS_SCHED_GET_PRIORITY_MAX] = (syscall_handler_t)sys_sched_get_priority_max;
    // syscall_handlers[SYS_SCHED_GET_PRIORITY_MIN] = (syscall_handler_t)sys_sched_get_priority_min;
    // syscall_handlers[SYS_SCHED_RR_GET_INTERVAL] = (syscall_handler_t)sys_sched_rr_get_interval;
    // syscall_handlers[SYS_MLOCK] = (syscall_handler_t)sys_mlock;
    // syscall_handlers[SYS_MUNLOCK] = (syscall_handler_t)sys_munlock;
    // syscall_handlers[SYS_MLOCKALL] = (syscall_handler_t)sys_mlockall;
    // syscall_handlers[SYS_MUNLOCKALL] = (syscall_handler_t)sys_munlockall;
    // syscall_handlers[SYS_VHANGUP] = (syscall_handler_t)sys_vhangup;
    // syscall_handlers[SYS_MODIFY_LDT] = (syscall_handler_t)sys_modify_ldt;
    // syscall_handlers[SYS_PIVOT_ROOT] = (syscall_handler_t)sys_pivot_root;
    // syscall_handlers[SYS__SYSCTL] = (syscall_handler_t)sys_sysctl;
    syscall_handlers[SYS_PRCTL] = (syscall_handler_t)sys_prctl;
    syscall_handlers[SYS_ARCH_PRCTL] = (syscall_handler_t)sys_arch_prctl;
    // syscall_handlers[SYS_ADJTIMEX] = (syscall_handler_t)sys_adjtimex;
    // syscall_handlers[SYS_SETRLIMIT] = (syscall_handler_t)sys_setrlimit;
    // syscall_handlers[SYS_CHROOT] = (syscall_handler_t)sys_chroot;
    // syscall_handlers[SYS_SYNC] = (syscall_handler_t)sys_sync;
    // syscall_handlers[SYS_ACCT] = (syscall_handler_t)sys_acct;
    // syscall_handlers[SYS_SETTIMEOFDAY] = (syscall_handler_t)sys_settimeofday;
    syscall_handlers[SYS_MOUNT] = (syscall_handler_t)sys_mount;
    // syscall_handlers[SYS_UMOUNT2] = (syscall_handler_t)sys_umount2;
    // syscall_handlers[SYS_SWAPON] = (syscall_handler_t)sys_swapon;
    // syscall_handlers[SYS_SWAPOFF] = (syscall_handler_t)sys_swapoff;
    syscall_handlers[SYS_REBOOT] = (syscall_handler_t)sys_reboot;
    // syscall_handlers[SYS_SETHOSTNAME] = (syscall_handler_t)sys_sethostname;
    // syscall_handlers[SYS_SETDOMAINNAME] = (syscall_handler_t)sys_setdomainname;
    // syscall_handlers[SYS_IOPL] = (syscall_handler_t)sys_iopl;
    // syscall_handlers[SYS_IOPERM] = (syscall_handler_t)sys_ioperm;
    // syscall_handlers[SYS_CREATE_MODULE] = (syscall_handler_t)sys_create_module;
    // syscall_handlers[SYS_INIT_MODULE] = (syscall_handler_t)sys_init_module;
    // syscall_handlers[SYS_DELETE_MODULE] = (syscall_handler_t)sys_delete_module;
    // syscall_handlers[SYS_GET_KERNEL_SYMS] = (syscall_handler_t)sys_get_kernel_syms;
    // syscall_handlers[SYS_QUERY_MODULE] = (syscall_handler_t)sys_query_module;
    // syscall_handlers[SYS_QUOTACTL] = (syscall_handler_t)sys_quotactl;
    // syscall_handlers[SYS_NFSSERVCTL] = (syscall_handler_t)sys_nfsservctl;
    // syscall_handlers[SYS_GETPMSG] = (syscall_handler_t)sys_getpmsg;
    // syscall_handlers[SYS_PUTPMSG] = (syscall_handler_t)sys_putpmsg;
    // syscall_handlers[SYS_AFS_SYSCALL] = (syscall_handler_t)sys_afs_syscall;
    // syscall_handlers[SYS_TUXCALL] = (syscall_handler_t)sys_tuxcall;
    // syscall_handlers[SYS_SECURITY] = (syscall_handler_t)sys_security;
    syscall_handlers[SYS_GETTID] = (syscall_handler_t)sys_gettid;
    // syscall_handlers[SYS_READAHEAD] = (syscall_handler_t)sys_readahead;
    // syscall_handlers[SYS_SETXATTR] = (syscall_handler_t)sys_setxattr;
    // syscall_handlers[SYS_LSETXATTR] = (syscall_handler_t)sys_lsetxattr;
    // syscall_handlers[SYS_FSETXATTR] = (syscall_handler_t)sys_fsetxattr;
    // syscall_handlers[SYS_GETXATTR] = (syscall_handler_t)sys_getxattr;
    // syscall_handlers[SYS_LGETXATTR] = (syscall_handler_t)sys_lgetxattr;
    // syscall_handlers[SYS_FGETXATTR] = (syscall_handler_t)sys_fgetxattr;
    // syscall_handlers[SYS_LISTXATTR] = (syscall_handler_t)sys_listxattr;
    // syscall_handlers[SYS_LLISTXATTR] = (syscall_handler_t)sys_llistxattr;
    // syscall_handlers[SYS_FLISTXATTR] = (syscall_handler_t)sys_flistxattr;
    // syscall_handlers[SYS_REMOVEXATTR] = (syscall_handler_t)sys_removexattr;
    // syscall_handlers[SYS_LREMOVEXATTR] = (syscall_handler_t)sys_lremovexattr;
    // syscall_handlers[SYS_FREMOVEXATTR] = (syscall_handler_t)sys_fremovexattr;
    // syscall_handlers[SYS_TKILL] = (syscall_handler_t)sys_tkill;
    // syscall_handlers[SYS_TIME] = (syscall_handler_t)sys_time;
    syscall_handlers[SYS_FUTEX] = (syscall_handler_t)sys_futex;
    syscall_handlers[SYS_SCHED_SETAFFINITY] = (syscall_handler_t)syscall_dummy_handler;
    syscall_handlers[SYS_SCHED_GETAFFINITY] = (syscall_handler_t)syscall_dummy_handler;
    // syscall_handlers[SYS_SET_THREAD_AREA] = (syscall_handler_t)sys_set_thread_area;
    // syscall_handlers[SYS_IO_SETUP] = (syscall_handler_t)sys_io_setup;
    // syscall_handlers[SYS_IO_DESTROY] = (syscall_handler_t)sys_io_destroy;
    // syscall_handlers[SYS_IO_GETEVENTS] = (syscall_handler_t)sys_io_getevents;
    // syscall_handlers[SYS_IO_SUBMIT] = (syscall_handler_t)sys_io_submit;
    // syscall_handlers[SYS_IO_CANCEL] = (syscall_handler_t)sys_io_cancel;
    // syscall_handlers[SYS_GET_THREAD_AREA] = (syscall_handler_t)sys_get_thread_area;
    // syscall_handlers[SYS_LOOKUP_DCOOKIE] = (syscall_handler_t)sys_lookup_dcookie;
    syscall_handlers[SYS_EPOLL_CREATE] = (syscall_handler_t)sys_epoll_create;
    // syscall_handlers[SYS_EPOLL_CTL_OLD] = (syscall_handler_t)sys_epoll_ctl_old;
    // syscall_handlers[SYS_EPOLL_WAIT_OLD] = (syscall_handler_t)sys_epoll_wait_old;
    // syscall_handlers[SYS_REMAP_FILE_PAGES] = (syscall_handler_t)sys_remap_file_pages;
    syscall_handlers[SYS_GETDENTS64] = (syscall_handler_t)sys_getdents;
    syscall_handlers[SYS_SET_TID_ADDRESS] = (syscall_handler_t)sys_set_tid_address;
    // syscall_handlers[SYS_RESTART_SYSCALL] = (syscall_handler_t)sys_restart_syscall;
    // syscall_handlers[SYS_SEMTIMEDOP] = (syscall_handler_t)sys_semtimedop;
    syscall_handlers[SYS_FADVISE64] = (syscall_handler_t)sys_fadvise64;
    syscall_handlers[SYS_TIMER_CREATE] = (syscall_handler_t)sys_timer_create;
    syscall_handlers[SYS_TIMER_SETTIME] = (syscall_handler_t)sys_timer_settime;
    // syscall_handlers[SYS_TIMER_GETTIME] = (syscall_handler_t)sys_timer_gettime;
    // syscall_handlers[SYS_TIMER_GETOVERRUN] = (syscall_handler_t)sys_timer_getoverrun;
    // syscall_handlers[SYS_TIMER_DELETE] = (syscall_handler_t)sys_timer_delete;
    // syscall_handlers[SYS_CLOCK_SETTIME] = (syscall_handler_t)sys_clock_settime;
    syscall_handlers[SYS_CLOCK_GETTIME] = (syscall_handler_t)sys_clock_gettime;
    syscall_handlers[SYS_CLOCK_GETRES] = (syscall_handler_t)sys_clock_getres;
    syscall_handlers[SYS_CLOCK_NANOSLEEP] = (syscall_handler_t)sys_nanosleep;
    syscall_handlers[SYS_EXIT_GROUP] = (syscall_handler_t)task_exit;
    syscall_handlers[SYS_EPOLL_WAIT] = (syscall_handler_t)sys_epoll_wait;
    syscall_handlers[SYS_EPOLL_CTL] = (syscall_handler_t)sys_epoll_ctl;
    // syscall_handlers[SYS_TGKILL] = (syscall_handler_t)sys_tkill;
    // syscall_handlers[SYS_UTIMES] = (syscall_handler_t)sys_utimes;
    // syscall_handlers[SYS_VSERVER] = (syscall_handler_t)sys_vserver;
    // syscall_handlers[SYS_MBIND] = (syscall_handler_t)sys_mbind;
    // syscall_handlers[SYS_SET_MEMPOLICY] = (syscall_handler_t)sys_set_mempolicy;
    // syscall_handlers[SYS_GET_MEMPOLICY] = (syscall_handler_t)sys_get_mempolicy;
    // syscall_handlers[SYS_MQ_OPEN] = (syscall_handler_t)sys_mq_open;
    // syscall_handlers[SYS_MQ_UNLINK] = (syscall_handler_t)sys_mq_unlink;
    // syscall_handlers[SYS_MQ_TIMEDSEND] = (syscall_handler_t)sys_mq_timedsend;
    // syscall_handlers[SYS_MQ_TIMEDRECEIVE] = (syscall_handler_t)sys_mq_timedreceive;
    // syscall_handlers[SYS_MQ_NOTIFY] = (syscall_handler_t)sys_mq_notify;
    // syscall_handlers[SYS_MQ_GETSETATTR] = (syscall_handler_t)sys_mq_getsetattr;
    // syscall_handlers[SYS_KEXEC_LOAD] = (syscall_handler_t)sys_kexec_load;
    // syscall_handlers[SYS_WAITID] = (syscall_handler_t)sys_waitid;
    // syscall_handlers[SYS_ADD_KEY] = (syscall_handler_t)sys_add_key;
    // syscall_handlers[SYS_REQUEST_KEY] = (syscall_handler_t)sys_request_key;
    // syscall_handlers[SYS_KEYCTL] = (syscall_handler_t)sys_keyctl;
    // syscall_handlers[SYS_IOPRIO_SET] = (syscall_handler_t)sys_ioprio_set;
    // syscall_handlers[SYS_IOPRIO_GET] = (syscall_handler_t)sys_ioprio_get;
    // syscall_handlers[SYS_INOTIFY_INIT] = (syscall_handler_t)sys_inotify_init;
    // syscall_handlers[SYS_INOTIFY_ADD_WATCH] = (syscall_handler_t)sys_inotify_add_watch;
    // syscall_handlers[SYS_INOTIFY_RM_WATCH] = (syscall_handler_t)sys_inotify_rm_watch;
    // syscall_handlers[SYS_MIGRATE_PAGES] = (syscall_handler_t)sys_migrate_pages;
    syscall_handlers[SYS_OPENAT] = (syscall_handler_t)sys_openat;
    // syscall_handlers[SYS_MKDIRAT] = (syscall_handler_t)sys_mkdirat;
    // syscall_handlers[SYS_MKNODAT] = (syscall_handler_t)sys_mknodat;
    // syscall_handlers[SYS_FCHOWNAT] = (syscall_handler_t)sys_fchownat;
    // syscall_handlers[SYS_FUTIMESAT] = (syscall_handler_t)sys_futimesat;
    syscall_handlers[SYS_NEWFSTATAT] = (syscall_handler_t)sys_newfstatat;
    syscall_handlers[SYS_UNLINKAT] = (syscall_handler_t)sys_unlinkat;
    syscall_handlers[SYS_RENAMEAT] = (syscall_handler_t)sys_renameat;
    // syscall_handlers[SYS_LINKAT] = (syscall_handler_t)sys_linkat;
    // syscall_handlers[SYS_SYMLINKAT] = (syscall_handler_t)sys_symlinkat;
    syscall_handlers[SYS_READLINKAT] = (syscall_handler_t)sys_readlinkat;
    // syscall_handlers[SYS_FCHMODAT] = (syscall_handler_t)sys_fchmodat;
    syscall_handlers[SYS_FACCESSAT] = (syscall_handler_t)sys_faccessat;
    syscall_handlers[SYS_PSELECT6] = (syscall_handler_t)sys_pselect6;
    syscall_handlers[SYS_PPOLL] = (syscall_handler_t)sys_ppoll;
    // syscall_handlers[SYS_UNSHARE] = (syscall_handler_t)sys_unshare;
    // syscall_handlers[SYS_SET_ROBUST_LIST] = (syscall_handler_t)sys_set_robust_list;
    // syscall_handlers[SYS_GET_ROBUST_LIST] = (syscall_handler_t)sys_get_robust_list;
    // syscall_handlers[SYS_SPLICE] = (syscall_handler_t)sys_splice;
    // syscall_handlers[SYS_TEE] = (syscall_handler_t)sys_tee;
    // syscall_handlers[SYS_SYNC_FILE_RANGE] = (syscall_handler_t)sys_sync_file_range;
    // syscall_handlers[SYS_VMSPLICE] = (syscall_handler_t)sys_vmsplice;
    // syscall_handlers[SYS_MOVE_PAGES] = (syscall_handler_t)sys_move_pages;
    // syscall_handlers[SYS_UTIMENSAT] = (syscall_handler_t)sys_utimensat;
    syscall_handlers[SYS_EPOLL_PWAIT] = (syscall_handler_t)sys_epoll_pwait;
    syscall_handlers[SYS_SIGNALFD] = (syscall_handler_t)sys_signalfd;
    syscall_handlers[SYS_TIMERFD_CREATE] = (syscall_handler_t)sys_timerfd_create;
    syscall_handlers[SYS_EVENTFD] = (syscall_handler_t)sys_eventfd_normal;
    syscall_handlers[SYS_FALLOCATE] = (syscall_handler_t)sys_fallocate;
    syscall_handlers[SYS_TIMERFD_SETTIME] = (syscall_handler_t)sys_timerfd_settime;
    // syscall_handlers[SYS_TIMERFD_GETTIME] = (syscall_handler_t)sys_timerfd_gettime;
    syscall_handlers[SYS_ACCEPT4] = (syscall_handler_t)sys_accept;
    syscall_handlers[SYS_SIGNALFD4] = (syscall_handler_t)sys_signalfd4;
    syscall_handlers[SYS_EVENTFD2] = (syscall_handler_t)sys_eventfd2;
    syscall_handlers[SYS_EPOLL_CREATE1] = (syscall_handler_t)sys_epoll_create1;
    syscall_handlers[SYS_DUP3] = (syscall_handler_t)sys_dup3;
    syscall_handlers[SYS_PIPE2] = (syscall_handler_t)sys_pipe;
    // syscall_handlers[SYS_INOTIFY_INIT1] = (syscall_handler_t)sys_inotify_init1;
    // syscall_handlers[SYS_PREADV] = (syscall_handler_t)sys_preadv;
    // syscall_handlers[SYS_PWRITEV] = (syscall_handler_t)sys_pwritev;
    // syscall_handlers[SYS_RT_TGSIGQUEUEINFO] = (syscall_handler_t)sys_rt_tgsigqueueinfo;
    // syscall_handlers[SYS_PERF_EVENT_OPEN] = (syscall_handler_t)sys_perf_event_open;
    // syscall_handlers[SYS_RECVMMSG] = (syscall_handler_t)sys_recvmmsg;
    // syscall_handlers[SYS_FANOTIFY_INIT] = (syscall_handler_t)sys_fanotify_init;
    // syscall_handlers[SYS_FANOTIFY_MARK] = (syscall_handler_t)sys_fanotify_mark;
    syscall_handlers[SYS_PRLIMIT64] = (syscall_handler_t)sys_prlimit64;
    // syscall_handlers[SYS_NAME_TO_HANDLE_AT] = (syscall_handler_t)sys_name_to_handle_at;
    // syscall_handlers[SYS_OPEN_BY_HANDLE_AT] = (syscall_handler_t)sys_open_by_handle_at;
    // syscall_handlers[SYS_CLOCK_ADJTIME] = (syscall_handler_t)sys_clock_adjtime;
    // syscall_handlers[SYS_SYNCFS] = (syscall_handler_t)sys_syncfs;
    // syscall_handlers[SYS_SENDMMSG] = (syscall_handler_t)sys_sendmmsg;
    // syscall_handlers[SYS_SETNS] = (syscall_handler_t)sys_setns;
    // syscall_handlers[SYS_GETCPU] = (syscall_handler_t)sys_getcpu;
    // syscall_handlers[SYS_PROCESS_VM_READV] = (syscall_handler_t)sys_process_vm_readv;
    // syscall_handlers[SYS_PROCESS_VM_WRITEV] = (syscall_handler_t)sys_process_vm_writev;
    // syscall_handlers[SYS_KCMP] = (syscall_handler_t)sys_kcmp;
    // syscall_handlers[SYS_FINIT_MODULE] = (syscall_handler_t)sys_finit_module;
    // syscall_handlers[SYS_SCHED_SETATTR] = (syscall_handler_t)sys_sched_setattr;
    // syscall_handlers[SYS_SCHED_GETATTR] = (syscall_handler_t)sys_sched_getattr;
    // syscall_handlers[SYS_RENAMEAT2] = (syscall_handler_t)sys_renameat2;
    // syscall_handlers[SYS_SECCOMP] = (syscall_handler_t)sys_seccomp;
    syscall_handlers[SYS_GETRANDOM] = (syscall_handler_t)sys_getrandom;
    syscall_handlers[SYS_MEMFD_CREATE] = (syscall_handler_t)sys_memfd_create;
    // syscall_handlers[SYS_KEXEC_FILE_LOAD] = (syscall_handler_t)sys_kexec_file_load;
    // syscall_handlers[SYS_BPF] = (syscall_handler_t)sys_bpf;
    // syscall_handlers[SYS_EXECVEAT] = (syscall_handler_t)sys_execveat;
    // syscall_handlers[SYS_USERFAULTFD] = (syscall_handler_t)sys_userfaultfd;
    syscall_handlers[SYS_MEMBARRIER] = (syscall_handler_t)sys_membarrier;
    // syscall_handlers[SYS_MLOCK2] = (syscall_handler_t)sys_mlock2;
    // syscall_handlers[SYS_COPY_FILE_RANGE] = (syscall_handler_t)sys_copy_file_range;
    // syscall_handlers[SYS_PREADV2] = (syscall_handler_t)sys_preadv2;
    // syscall_handlers[SYS_PWRITEV2] = (syscall_handler_t)sys_pwritev2;
    // syscall_handlers[SYS_PKEY_MPROTECT] = (syscall_handler_t)sys_pkey_mprotect;
    // syscall_handlers[SYS_PKEY_ALLOC] = (syscall_handler_t)sys_pkey_alloc;
    // syscall_handlers[SYS_PKEY_FREE] = (syscall_handler_t)sys_pkey_free;
    syscall_handlers[SYS_STATX] = (syscall_handler_t)sys_statx;
    // syscall_handlers[SYS_IO_PGETEVENTS] = (syscall_handler_t)sys_io_pgetevents;
    syscall_handlers[SYS_RSEQ] = (syscall_handler_t)syscall_dummy_handler;
    // syscall_handlers[SYS_PIDFD_SEND_SIGNAL] = (syscall_handler_t)sys_pidfd_send_signal;
    // syscall_handlers[SYS_IO_URING_SETUP] = (syscall_handler_t)sys_io_uring_setup;
    // syscall_handlers[SYS_IO_URING_ENTER] = (syscall_handler_t)sys_io_uring_enter;
    // syscall_handlers[SYS_IO_URING_REGISTER] = (syscall_handler_t)sys_io_uring_register;
    // syscall_handlers[SYS_OPEN_TREE] = (syscall_handler_t)sys_open_tree;
    // syscall_handlers[SYS_MOVE_MOUNT] = (syscall_handler_t)sys_move_mount;
    // syscall_handlers[SYS_FSOPEN] = (syscall_handler_t)sys_fsopen;
    // syscall_handlers[SYS_FSCONFIG] = (syscall_handler_t)sys_fsconfig;
    // syscall_handlers[SYS_FSMOUNT] = (syscall_handler_t)sys_fsmount;
    // syscall_handlers[SYS_FSPICK] = (syscall_handler_t)sys_fspick;
    // syscall_handlers[SYS_PIDFD_OPEN] = (syscall_handler_t)sys_pidfd_open;
    // syscall_handlers[SYS_CLONE3] = (syscall_handler_t)sys_clone3;
    syscall_handlers[SYS_CLOSE_RANGE] = (syscall_handler_t)sys_close_range;
    // syscall_handlers[SYS_OPENAT2] = (syscall_handler_t)sys_openat2;
    // syscall_handlers[SYS_PIDFD_GETFD] = (syscall_handler_t)sys_pidfd_getfd;
    syscall_handlers[SYS_FACCESSAT2] = (syscall_handler_t)sys_faccessat2;
    // syscall_handlers[SYS_PROCESS_MADVISE] = (syscall_handler_t)sys_process_madvise;
    // syscall_handlers[SYS_EPOLL_PWAIT2] = (syscall_handler_t)sys_epoll_pwait2;
    // syscall_handlers[SYS_MOUNT_SETATTR] = (syscall_handler_t)sys_mount_setattr;
    // syscall_handlers[SYS_LANDLOCK_CREATE_RULESET] = (syscall_handler_t)sys_landlock_create_ruleset;
    // syscall_handlers[SYS_LANDLOCK_ADD_RULE] = (syscall_handler_t)sys_landlock_add_rule;
    // syscall_handlers[SYS_LANDLOCK_RESTRICT_SELF] = (syscall_handler_t)sys_landlock_restrict_self;
    // syscall_handlers[SYS_MEMFD_SECRET] = (syscall_handler_t)sys_memfd_secret;
    // syscall_handlers[SYS_PROCESS_MRELEASE] = (syscall_handler_t)sys_process_mrelease;
    // syscall_handlers[SYS_FUTEX_WAITV] = (syscall_handler_t)sys_futex_waitv;
    // syscall_handlers[SYS_SET_MEMPOLICY_HOME_NODE] = (syscall_handler_t)sys_set_mempolicy_home_node;
    // syscall_handlers[SYS_CACHESTAT] = (syscall_handler_t)sys_cachestat;
    // syscall_handlers[SYS_FCHMODAT2] = (syscall_handler_t)sys_fchmodat2;
}

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

    if (idx > NR_SYSCALL || !syscall_handlers[idx])
    {
        char buf[32];
        int len = sprintf(buf, "syscall %d not implemented\n", idx);
        serial_printk(buf, len);
        regs->rax = (uint64_t)-ENOSYS;
        return;
    }

    if (syscall_handlers[idx] == (syscall_handler_t)syscall_dummy_handler)
    {
        char buf[64];
        int len = sprintf(buf, "syscall %d is the dummy handler\n", idx);
        serial_printk(buf, len);
    }

    if (idx == SYS_FORK || idx == SYS_VFORK || idx == SYS_CLONE || idx == SYS_CLONE3 || idx == SYS_RT_SIGRETURN)
    {
        regs->rax = ((special_syscall_handler_t)syscall_handlers[idx])(regs, arg1, arg2, arg3, arg4, arg5, arg6);
    }
    else
    {
        regs->rax = syscall_handlers[idx](arg1, arg2, arg3, arg4, arg5, arg6);
        if ((int)regs->rax < 0)
        {
            regs->rax |= 0xffffffff00000000;
        }
    }
}
