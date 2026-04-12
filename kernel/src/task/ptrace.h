#pragma once

#include <fs/fs_syscall.h>
#include <task/task.h>

#define PTRACE_TRACEME 0
#define PTRACE_PEEKTEXT 1
#define PTRACE_PEEKDATA 2
#define PTRACE_PEEKUSER 3
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
#define PTRACE_POKEUSER 6
#define PTRACE_CONT 7
#define PTRACE_KILL 8
#define PTRACE_SINGLESTEP 9
#define PTRACE_GETREGS 12
#define PTRACE_SETREGS 13
#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17
#define PTRACE_SYSCALL 24
#define PTRACE_SETOPTIONS 0x4200
#define PTRACE_GETEVENTMSG 0x4201
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SETSIGINFO 0x4203
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207
#define PTRACE_LISTEN 0x4208
#define PTRACE_GET_SYSCALL_INFO 0x420e

#define PTRACE_O_TRACESYSGOOD 0x00000001U
#define PTRACE_O_TRACEFORK 0x00000002U
#define PTRACE_O_TRACEVFORK 0x00000004U
#define PTRACE_O_TRACECLONE 0x00000008U
#define PTRACE_O_TRACEEXEC 0x00000010U
#define PTRACE_O_TRACEVFORKDONE 0x00000020U
#define PTRACE_O_TRACEEXIT 0x00000040U
#define PTRACE_O_TRACESECCOMP 0x00000080U
#define PTRACE_O_EXITKILL 0x00100000U

#define PTRACE_EVENT_FORK 1
#define PTRACE_EVENT_VFORK 2
#define PTRACE_EVENT_CLONE 3
#define PTRACE_EVENT_EXEC 4
#define PTRACE_EVENT_VFORK_DONE 5
#define PTRACE_EVENT_EXIT 6
#define PTRACE_EVENT_SECCOMP 7

#define PTRACE_SYSCALL_INFO_NONE 0
#define PTRACE_SYSCALL_INFO_ENTRY 1
#define PTRACE_SYSCALL_INFO_EXIT 2
#define PTRACE_SYSCALL_INFO_SECCOMP 3

#define PTRACE_RESUME_NONE 0
#define PTRACE_RESUME_CONT 1
#define PTRACE_RESUME_SYSCALL 2

#define PTRACE_STOP_NONE 0
#define PTRACE_STOP_SIGNAL 1
#define PTRACE_STOP_SYSCALL_ENTER 2
#define PTRACE_STOP_SYSCALL_EXIT 3

#define AUDIT_ARCH_X86_64 0xc000003eU
#define AUDIT_ARCH_AARCH64 0xc00000b7U

struct ptrace_syscall_info {
    uint8_t op;
    uint8_t pad[3];
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    union {
        struct {
            uint64_t nr;
            uint64_t args[6];
        } entry;
        struct {
            int64_t rval;
            uint8_t is_error;
            uint8_t pad[7];
        } exit;
        struct {
            uint64_t nr;
            uint64_t args[6];
            uint32_t ret_data;
        } seccomp;
    };
};

static inline bool ptrace_is_traced(const task_t *task) {
    return task && task->ptrace_tracer_pid != 0;
}

static inline bool ptrace_signal_should_stop(int sig) {
    return sig == SIGSTOP || sig == SIGTRAP || sig == SIGTSTP ||
           sig == SIGTTIN || sig == SIGTTOU;
}

uint64_t sys_ptrace(uint64_t request, uint64_t pid, void *addr, void *data);
bool ptrace_matches_waiter(const task_t *task, const task_t *waiter);
bool ptrace_has_wait_event(const task_t *task);
bool ptrace_consume_wait_event(task_t *task, int *status, siginfo_t *info,
                               bool nowait);
void ptrace_resume_from_signal(task_t *task);
void ptrace_on_syscall_enter(struct pt_regs *regs);
void ptrace_on_syscall_exit(struct pt_regs *regs);
void ptrace_stop_for_signal(task_t *task, int sig, const siginfo_t *info);
void ptrace_stop_for_exec(task_t *task);
