#pragma once

#include <arch/arch.h>
#include <task/task_struct.h>
#include <task/signal.h>
#include <fs/termios.h>
#include <mm/bitmap.h>

#define IDLE_PRIORITY NICE_TO_PRIO(20)
#define NORMAL_PRIORITY NICE_TO_PRIO(0)
#define KTHREAD_PRIORITY NICE_TO_PRIO(-1)

#define AT_NULL 0
#define AT_IGNORE 1
#define AT_EXECFD 2
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_FLAGS 8
#define AT_ENTRY 9
#define AT_NOTELF 10
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14
#define AT_CLKTCK 17
#define AT_PLATFORM 15
#define AT_HWCAP 16
#define AT_FPUCW 18
#define AT_DCACHEBSIZE 19
#define AT_ICACHEBSIZE 20
#define AT_UCACHEBSIZE 21
#define AT_IGNOREPPC 22
#define AT_SECURE 23
#define AT_BASE_PLATFORM 24
#define AT_RANDOM 25
#define AT_HWCAP2 26
#define AT_EXECFN 31
#define AT_SYSINFO 32
#define AT_SYSINFO_EHDR 33

#define INTERPRETER_BASE_ADDR 0x0000000020000000

#define USER_MMAP_START 0x0000000040000000
#define USER_MMAP_END 0x0000000080000000

#define USER_BRK_START 0x0000000080000000
#define USER_BRK_END 0x0000000100000000

#define CLONE_VM 0x00000100 /* set if VM shared between processes */
#define CLONE_FS 0x00000200 /* set if fs info shared between processes */
#define CLONE_FILES                                                            \
    0x00000400 /* set if open files shared between processes                   \
                */
#define CLONE_SIGHAND                                                          \
    0x00000800 /* set if signal handlers and blocked signals shared */
#define CLONE_PIDFD 0x00001000 /* set if a pidfd should be placed in parent */
#define CLONE_PTRACE                                                           \
    0x00002000 /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK                                                            \
    0x00004000 /* set if the parent wants the child to wake it up on           \
                  mm_release */
#define CLONE_PARENT                                                           \
    0x00008000 /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD 0x00010000         /* Same thread group? */
#define CLONE_NEWNS 0x00020000          /* New mount namespace group */
#define CLONE_SYSVSEM 0x00040000        /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS 0x00080000         /* create a new TLS for the child */
#define CLONE_PARENT_SETTID 0x00100000  /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID 0x00200000 /* clear the TID in the child */
#define CLONE_DETACHED 0x00400000       /* Unused, ignored */
#define CLONE_UNTRACED                                                         \
    0x00800000 /* set if the tracing process can't force CLONE_PTRACE on this  \
                  clone */
#define CLONE_CHILD_SETTID 0x01000000 /* set the TID in the child */
#define CLONE_NEWCGROUP 0x02000000    /* New cgroup namespace */
#define CLONE_NEWUTS 0x04000000       /* New utsname namespace */
#define CLONE_NEWIPC 0x08000000       /* New ipc namespace */
#define CLONE_NEWUSER 0x10000000      /* New user namespace */
#define CLONE_NEWPID 0x20000000       /* New pid namespace */
#define CLONE_NEWNET 0x40000000       /* New network namespace */
#define CLONE_IO 0x80000000           /* Clone io context */

extern task_t *arch_get_current();

#define current_task arch_get_current()

void sched_update_itimer();
void sched_update_timerfd();
void sched_check_wakeup();

task_t *task_create(const char *name, void (*entry)(uint64_t), uint64_t arg,
                    int priority);
void task_init();

struct pt_regs;

uint64_t task_fork(struct pt_regs *regs, bool vfork);
uint64_t task_execve(const char *path, const char **argv, const char **envp);
uint64_t task_exit(int64_t code);

#define WNOHANG 1
#define WUNTRACED 2

uint64_t sys_waitpid(uint64_t pid, int *status, uint64_t options);
uint64_t sys_clone(struct pt_regs *regs, uint64_t flags, uint64_t newsp,
                   int *parent_tid, int *child_tid, uint64_t tls);
struct timespec;
uint64_t sys_nanosleep(struct timespec *req, struct timespec *rem);

size_t sys_setitimer(int which, struct itimerval *value, struct itimerval *old);

int task_block(task_t *task, task_state_t state, int64_t timeout_ns);
void task_unblock(task_t *task, int reason);

#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_SET_SECCOMP 22
#define PR_GET_SECCOMP 21
#define PR_SET_TIMERSLACK 23
#define SECCOMP_MODE_STRICT 1

uint64_t sys_prctl(uint64_t options, uint64_t arg2, uint64_t arg3,
                   uint64_t arg4, uint64_t arg5);

uint64_t sys_timer_create(clockid_t clockid, struct sigevent *sevp,
                          timer_t *timerid);
uint64_t sys_timer_settime(timer_t timerid, const struct itimerval *new_value,
                           struct itimerval *old_value);

uint64_t sys_reboot(int magic1, int magic2, uint32_t cmd, void *arg);

static inline uint64_t sys_getpgid(uint64_t pid) { return 0; }

static inline uint64_t sys_setpgid(uint64_t pid, uint64_t pgid) { return 0; }

static inline uint64_t sys_getuid() { return current_task->uid; }

static inline uint64_t sys_setuid(uint64_t uid) {
    current_task->uid = uid;
    return 0;
}

static inline uint64_t sys_getgid() { return current_task->gid; }

static inline uint64_t sys_geteuid() { return current_task->euid; }

static inline uint64_t sys_getegid() { return current_task->egid; }

static inline uint64_t sys_getresuid(uint64_t *ruid, uint64_t *euid,
                                     uint64_t *suid) {
    *ruid = current_task->ruid;
    *euid = current_task->euid;
    *suid = current_task->uid;

    return 0;
}

static inline uint64_t sys_getresgid(uint64_t *rgid, uint64_t *egid,
                                     uint64_t *sgid) {
    *rgid = current_task->rgid;
    *egid = current_task->egid;
    *sgid = current_task->gid;

    return 0;
}

static inline uint64_t sys_setgid(uint64_t gid) {
    current_task->gid = gid;
    return 0;
}

static inline uint64_t sys_getsid(uint64_t pid) { return 0; }

static inline uint64_t sys_setsid() { return 0; }

static inline uint64_t sys_fork(struct pt_regs *regs) {
    return task_fork(regs, false);
}

static inline uint64_t sys_vfork(struct pt_regs *regs) {
    return task_fork(regs, true);
}

static inline uint64_t sys_getpid() { return current_task->pid; }

static inline uint64_t sys_getppid() { return current_task->ppid; }

static inline uint64_t sys_getgroups(int gidsetsize, uint32_t *gids) {
    if (!gidsetsize)
        return 1;

    gids[0] = 0;
    return 1;
}

static inline uint64_t sys_getcpu(unsigned *cpup, unsigned *nodep,
                                  void *unused) {
    *cpup = current_cpu_id;
    *nodep = 0;

    return 0;
}

static inline uint64_t sys_set_tid_address(int *ptr) {
    current_task->tidptr = ptr;
    return 0;
}

#define PRIO_PROCESS 0
#define PRIO_PGRP 1
#define PRIO_USER 2

uint64_t sys_setpriority(int which, int who, int niceval);

extern task_t *tasks[MAX_TASK_NUM];
extern task_t *idle_tasks[MAX_CPU_NUM];

extern struct eevdf_t *schedulers[MAX_CPU_NUM];

void schedule();
