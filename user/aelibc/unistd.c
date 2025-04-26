#include <unistd.h>

int open(const char *name, int mode, int flags)
{
    return (int)enter_syscall((uint64_t)name, mode, flags, 0, 0, SYS_OPEN);
}

int close(int fd)
{
    return (int)enter_syscall(fd, 0, 0, 0, 0, SYS_CLOSE);
}

ssize_t read(int fd, void *buf, size_t count)
{
    return (ssize_t)enter_syscall(fd, (uint64_t)buf, count, 0, 0, SYS_READ);
}

ssize_t write(int fd, void *buf, size_t count)
{
    return (ssize_t)enter_syscall(fd, (uint64_t)buf, count, 0, 0, SYS_WRITE);
}

off_t lseek(int fd, off_t offset, int whence)
{
    return (off_t)enter_syscall(fd, offset, whence, 0, 0, SYS_LSEEK);
}

int fork()
{
    return enter_syscall(0, 0, 0, 0, 0, SYS_FORK);
}

int execve(const char *name, char **argv, char **envp)
{
    return enter_syscall((uint64_t)name, (uint64_t)argv, (uint64_t)envp, 0, 0, SYS_EXECVE);
}

int getpid()
{
    return enter_syscall(0, 0, 0, 0, 0, SYS_GETPID);
}

int getppid()
{
    return enter_syscall(0, 0, 0, 0, 0, SYS_GETPPID);
}
