#pragma once

#include <fs/vfs/vfs.h>
#include <fs/proc.h>
#include <task/task.h>
#include <task/sched.h>
#include <fs/fs_syscall.h>

uint64_t task_fork(struct pt_regs *regs, bool vfork);

#define WNOHANG 0x00000001
#define WUNTRACED 0x00000002
#define WSTOPPED WUNTRACED
#define WEXITED 0x00000004
#define WCONTINUED 0x00000008
#define WNOWAIT 0x01000000

/* idtype for waitid */
#define P_ALL 0
#define P_PID 1
#define P_PGID 2
#define P_PIDFD 3

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN (-1)
#define RUSAGE_THREAD 1

uint64_t sys_waitpid(uint64_t pid, int *status, uint64_t options,
                     struct rusage *rusage);
uint64_t sys_waitid(int idtype, uint64_t id, siginfo_t *infop, int options,
                    struct rusage *rusage);
uint64_t sys_getrusage(int who, struct rusage *ru);
uint64_t sys_clone(struct pt_regs *regs, uint64_t flags, uint64_t newsp,
                   int *parent_tid, int *child_tid, uint64_t tls);

typedef struct clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
} clone_args_t;

uint64_t sys_clone3(struct pt_regs *regs, clone_args_t *args,
                    uint64_t args_size);

struct timespec;
uint64_t sys_nanosleep(struct timespec *req, struct timespec *rem);
uint64_t sys_clock_nanosleep(int clock_id, int flags,
                             const struct timespec *request,
                             struct timespec *remain);

#define SCHED_OTHER 0
#define SCHED_FIFO 1
#define SCHED_RR 2
#define SCHED_BATCH 3
#define SCHED_IDLE 5
#define SCHED_DEADLINE 6
#define SCHED_RESET_ON_FORK 0x40000000

struct sched_param {
    int sched_priority;
};

uint64_t sys_sched_setparam(int pid, const struct sched_param *param);
uint64_t sys_sched_getparam(int pid, struct sched_param *param);
uint64_t sys_sched_setscheduler(int pid, int policy,
                                const struct sched_param *param);
uint64_t sys_sched_getscheduler(int pid);
uint64_t sys_sched_get_priority_max(int policy);
uint64_t sys_sched_get_priority_min(int policy);
uint64_t sys_sched_rr_get_interval(int pid, struct timespec *interval);
uint64_t sys_sched_setaffinity(int pid, size_t len,
                               const unsigned long *user_mask_ptr);
uint64_t sys_sched_getaffinity(int pid, size_t len,
                               unsigned long *user_mask_ptr);

size_t sys_setitimer(int which, struct itimerval *value, struct itimerval *old);

#define PR_SET_PDEATHSIG 1
#define PR_GET_PDEATHSIG 2
#define PR_GET_DUMPABLE 3
#define PR_SET_DUMPABLE 4
#define PR_GET_UNALIGN 5
#define PR_SET_UNALIGN 6
#define PR_UNALIGN_NOPRINT 1
#define PR_UNALIGN_SIGBUS 2
#define PR_GET_KEEPCAPS 7
#define PR_SET_KEEPCAPS 8
#define PR_GET_FPEMU 9
#define PR_SET_FPEMU 10
#define PR_FPEMU_NOPRINT 1
#define PR_FPEMU_SIGFPE 2
#define PR_GET_FPEXC 11
#define PR_SET_FPEXC 12
#define PR_FP_EXC_SW_ENABLE 0x80
#define PR_FP_EXC_DIV 0x010000
#define PR_FP_EXC_OVF 0x020000
#define PR_FP_EXC_UND 0x040000
#define PR_FP_EXC_RES 0x080000
#define PR_FP_EXC_INV 0x100000
#define PR_FP_EXC_DISABLED 0
#define PR_FP_EXC_NONRECOV 1
#define PR_FP_EXC_ASYNC 2
#define PR_FP_EXC_PRECISE 3
#define PR_GET_TIMING 13
#define PR_SET_TIMING 14
#define PR_TIMING_STATISTICAL 0
#define PR_TIMING_TIMESTAMP 1
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_GET_ENDIAN 19
#define PR_SET_ENDIAN 20
#define PR_ENDIAN_BIG 0
#define PR_ENDIAN_LITTLE 1
#define PR_ENDIAN_PPC_LITTLE 2
#define PR_GET_SECCOMP 21
#define PR_SET_SECCOMP 22
#define PR_CAPBSET_READ 23
#define PR_CAPBSET_DROP 24
#define PR_GET_TSC 25
#define PR_SET_TSC 26
#define PR_TSC_ENABLE 1
#define PR_TSC_SIGSEGV 2
#define PR_GET_SECUREBITS 27
#define PR_SET_SECUREBITS 28
#define PR_SET_TIMERSLACK 29
#define PR_GET_TIMERSLACK 30

#define PR_TASK_PERF_EVENTS_DISABLE 31
#define PR_TASK_PERF_EVENTS_ENABLE 32

#define PR_MCE_KILL 33
#define PR_MCE_KILL_CLEAR 0
#define PR_MCE_KILL_SET 1
#define PR_MCE_KILL_LATE 0
#define PR_MCE_KILL_EARLY 1
#define PR_MCE_KILL_DEFAULT 2
#define PR_MCE_KILL_GET 34

#define PR_SET_MM 35
#define PR_SET_MM_START_CODE 1
#define PR_SET_MM_END_CODE 2
#define PR_SET_MM_START_DATA 3
#define PR_SET_MM_END_DATA 4
#define PR_SET_MM_START_STACK 5
#define PR_SET_MM_START_BRK 6
#define PR_SET_MM_BRK 7
#define PR_SET_MM_ARG_START 8
#define PR_SET_MM_ARG_END 9
#define PR_SET_MM_ENV_START 10
#define PR_SET_MM_ENV_END 11
#define PR_SET_MM_AUXV 12
#define PR_SET_MM_EXE_FILE 13
#define PR_SET_MM_MAP 14
#define PR_SET_MM_MAP_SIZE 15

#define PR_SET_PTRACER 0x59616d61
#define PR_SET_PTRACER_ANY (-1UL)

#define PR_SET_CHILD_SUBREAPER 36
#define PR_GET_CHILD_SUBREAPER 37

#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39

#define PR_GET_TID_ADDRESS 40

#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42

#define PR_MPX_ENABLE_MANAGEMENT 43
#define PR_MPX_DISABLE_MANAGEMENT 44

#define PR_SET_FP_MODE 45
#define PR_GET_FP_MODE 46
#define PR_FP_MODE_FR (1 << 0)
#define PR_FP_MODE_FRE (1 << 1)

#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_IS_SET 1
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_LOWER 3
#define PR_CAP_AMBIENT_CLEAR_ALL 4

uint64_t sys_prctl(uint64_t options, uint64_t arg2, uint64_t arg3,
                   uint64_t arg4, uint64_t arg5);
uint64_t sys_seccomp(uint64_t operation, uint64_t flags, void *uargs);
uint64_t sys_set_robust_list(void *head, size_t len);
uint64_t sys_get_robust_list(int pid, void **head_ptr, size_t *len_ptr);
uint64_t sys_rseq(void *rseq, uint32_t rseq_len, int flags, uint32_t sig);
uint64_t sys_alarm(uint64_t seconds);
uint64_t sys_timer_create(clockid_t clockid, struct sigevent *sevp,
                          timer_t *timerid);
uint64_t sys_timer_settime(timer_t timerid, const struct itimerval *new_value,
                           struct itimerval *old_value);

uint64_t sys_reboot(int magic1, int magic2, uint32_t cmd, void *arg);

uint64_t sys_getpgid(uint64_t pid);
uint64_t sys_setpgid(uint64_t pid, uint64_t pgid);
uint64_t sys_getsid(uint64_t pid);
uint64_t sys_setsid(void);

static inline uint64_t sys_getuid() { return current_task->uid; }

static inline int64_t cred_keep_or_set(int value, int64_t current) {
    return value == -1 ? current : value;
}

static inline uint64_t sys_setuid(uint64_t uid) {
    if (uid == (uint64_t)-1)
        return (uint64_t)-EINVAL;

    current_task->uid = uid;
    current_task->euid = uid;
    current_task->suid = uid;
    return 0;
}

static inline uint64_t sys_getgid() { return current_task->gid; }

static inline uint64_t sys_geteuid() { return current_task->euid; }

static inline uint64_t sys_getegid() { return current_task->egid; }

static inline uint64_t sys_getresuid(int *ruid, int *euid, int *suid) {
    int value;

    if (ruid) {
        value = current_task->uid;
        if (copy_to_user(ruid, &value, sizeof(value)))
            return (uint64_t)-EFAULT;
    }
    if (euid) {
        value = current_task->euid;
        if (copy_to_user(euid, &value, sizeof(value)))
            return (uint64_t)-EFAULT;
    }
    if (suid) {
        value = current_task->suid;
        if (copy_to_user(suid, &value, sizeof(value)))
            return (uint64_t)-EFAULT;
    }

    return 0;
}

static inline uint64_t sys_setresuid(int ruid, int euid, int suid) {
    current_task->uid = cred_keep_or_set(ruid, current_task->uid);
    current_task->euid = cred_keep_or_set(euid, current_task->euid);
    current_task->suid = cred_keep_or_set(suid, current_task->suid);

    return 0;
}

static inline uint64_t sys_setreuid(int ruid, int euid) {
    int64_t old_ruid = current_task->uid;

    current_task->uid = cred_keep_or_set(ruid, current_task->uid);
    current_task->euid = cred_keep_or_set(euid, current_task->euid);
    if (ruid != -1 || (euid != -1 && current_task->euid != old_ruid))
        current_task->suid = current_task->euid;

    return 0;
}

static inline uint64_t sys_getresgid(int *rgid, int *egid, int *sgid) {
    int value;

    if (rgid) {
        value = current_task->gid;
        if (copy_to_user(rgid, &value, sizeof(value)))
            return (uint64_t)-EFAULT;
    }
    if (egid) {
        value = current_task->egid;
        if (copy_to_user(egid, &value, sizeof(value)))
            return (uint64_t)-EFAULT;
    }
    if (sgid) {
        value = current_task->sgid;
        if (copy_to_user(sgid, &value, sizeof(value)))
            return (uint64_t)-EFAULT;
    }

    return 0;
}

static inline uint64_t sys_setresgid(int rgid, int egid, int sgid) {
    current_task->gid = cred_keep_or_set(rgid, current_task->gid);
    current_task->egid = cred_keep_or_set(egid, current_task->egid);
    current_task->sgid = cred_keep_or_set(sgid, current_task->sgid);

    return 0;
}

static inline uint64_t sys_setregid(int rgid, int egid) {
    int64_t old_rgid = current_task->gid;

    current_task->gid = cred_keep_or_set(rgid, current_task->gid);
    current_task->egid = cred_keep_or_set(egid, current_task->egid);
    if (rgid != -1 || (egid != -1 && current_task->egid != old_rgid))
        current_task->sgid = current_task->egid;

    return 0;
}

static inline uint64_t sys_setgid(uint64_t gid) {
    if (gid == (uint64_t)-1)
        return (uint64_t)-EINVAL;

    current_task->gid = gid;
    current_task->egid = gid;
    current_task->sgid = gid;
    return 0;
}

static inline uint64_t sys_fork(struct pt_regs *regs) {
    return task_fork(regs, false);
}

static inline uint64_t sys_vfork(struct pt_regs *regs) {
    return task_fork(regs, true);
}

static inline uint64_t sys_getpid() {
    return task_effective_tgid(current_task);
}

static inline uint64_t sys_gettid() { return current_task->pid; }

static inline uint64_t sys_getppid() { return current_task->ppid; }

static inline uint64_t sys_getpgrp() { return current_task->pgid; }

static inline uint64_t sys_getgroups(int gidsetsize, int *gids) {
    if (!gidsetsize)
        return 1;

    if (!gids)
        return (uint64_t)-EFAULT;

    int gid = 0;
    if (copy_to_user(gids, &gid, sizeof(gid)))
        return (uint64_t)-EFAULT;

    return 1;
}

static inline uint64_t sys_getcpu(unsigned *cpup, unsigned *nodep,
                                  void *unused) {
    (void)unused;

    if (cpup) {
        unsigned cpu = current_cpu_id;
        if (copy_to_user(cpup, &cpu, sizeof(cpu)))
            return (uint64_t)-EFAULT;
    }
    if (nodep) {
        unsigned node = 0;
        if (copy_to_user(nodep, &node, sizeof(node)))
            return (uint64_t)-EFAULT;
    }

    return 0;
}

static inline uint64_t sys_set_tid_address(int *ptr) {
    current_task->tidptr = ptr;
    return current_task->pid;
}

#define PRIO_PROCESS 0
#define PRIO_PGRP 1
#define PRIO_USER 2

uint64_t sys_setpriority(int which, int who, int niceval);
