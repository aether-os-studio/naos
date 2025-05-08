#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>
#include <mm/mm_syscall.h>

void syscall_init()
{
}

extern uint64_t time_read();

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
    case SYS_OPEN:
        ret = sys_open((const char *)arg1, arg2, arg3);
        break;
    case SYS_CLOSE:
        ret = sys_close(arg1);
        break;
    case SYS_LSEEK:
        ret = sys_lseek(arg1, arg2, arg3);
        break;
    case SYS_READ:
        ret = sys_read(arg1, (void *)arg2, arg3);
        break;
    case SYS_WRITE:
        ret = sys_write(arg1, (const void *)arg2, arg3);
        break;
    case SYS_IOCTL:
        ret = sys_ioctl(arg1, arg2, arg3);
        break;
    case SYS_READV:
        ret = sys_readv(arg1, (struct iovec *)arg2, arg3);
        break;
    case SYS_WRITEV:
        ret = sys_writev(arg1, (struct iovec *)arg2, arg3);
        break;
    case SYS_FORK:
        ret = task_fork(frame);
        break;
    case SYS_EXECVE:
        ret = task_execve((const char *)arg1, (char *const *)arg2, (char *const *)arg3);
        break;
    case SYS_EXIT:
        ret = task_exit((int64_t)arg1);
        break;
    case SYS_EXIT_GROUP:
        ret = task_exit((int64_t)arg1);
        break;
    case SYS_GETPID:
        ret = current_task->pid;
        break;
    case SYS_GETPPID:
        ret = current_task->ppid;
        break;
    case SYS_WAIT4:
        ret = sys_waitpid(arg1, (int *)arg2);
        break;
    case SYS_BRK:
        ret = sys_brk(arg1);
        break;
    case SYS_SIGNAL:
        ret = sys_signal(arg1, arg2, arg3);
        break;
    case SYS_SETMASK:
        ret = sys_ssetmask(arg1, (sigset_t *)arg2, (sigset_t *)arg3);
        break;
    case SYS_GETDENTS:
        ret = sys_getdents(arg1, arg2, arg3);
        break;
    case SYS_CHDIR:
        ret = sys_chdir((const char *)arg1);
        break;
    case SYS_GETCWD:
        ret = sys_getcwd((char *)arg1, arg2);
        break;
    case SYS_MMAP:
        ret = sys_mmap(arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    case SYS_CLOCK_GETTIME:
        *(int64_t *)arg1 = time_read();
        *(int64_t *)arg2 = 0;
        ret = 0;
        break;

    default:
        ret = (uint64_t)-ENOSYS;
        break;
    }

    frame->x0 = ret;
}
