#pragma once

/*
 * Linux x86_64系统调用号定义文件 (基于Linux 5.15内核)
 * 说明：
 * 1. 系统调用号可能因内核版本不同而变化，建议通过/usr/include/asm/unistd_64.h获取官方定义
 * 2. 参数传递规则：RDI, RSI, RDX, R10, R8, R9 对应参数1-6
 * 3. 系统调用号通过RAX寄存器传递
 */

/* 文件操作相关 */
#define SYS_READ 0      // read(int fd, void *buf, size_t count)
#define SYS_WRITE 1     // write(int fd, const void *buf, size_t count)
#define SYS_OPEN 2      // open(const char *pathname, int flags, mode_t mode)
#define SYS_CLOSE 3     // close(int fd)
#define SYS_STAT 4      // stat(const char *pathname, struct stat *statbuf)
#define SYS_FSTAT 5     // fstat(int fd, struct stat *statbuf)
#define SYS_LSTAT 6     // lstat(const char *pathname, struct stat *statbuf)
#define SYS_POLL 7      // poll(struct pollfd *fds, nfds_t nfds, int timeout)
#define SYS_LSEEK 8     // lseek(int fd, off_t offset, int whence)
#define SYS_MMAP 9      // mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
#define SYS_MPROTECT 10 // mprotect(void *addr, size_t len, int prot)
#define SYS_MUNMAP 11   // munmap(void *addr, size_t length)
#define SYS_BRK 12      // brk(void *addr)
#define SYS_READV 19
#define SYS_WRITEV 20
#define SYS_IOCTL 16 // ioctl(int fd, sint cmd, int arg)

/* 进程管理相关 */
#define SYS_FORK 57     // fork()
#define SYS_VFORK 58    // vfork()
#define SYS_EXECVE 59   // execve(const char *pathname, char *const argv[], char *const envp[])
#define SYS_EXIT 60     // exit(int status)
#define SYS_WAIT4 61    // wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage)
#define SYS_KILL 62     // kill(pid_t pid, int sig)
#define SYS_GETPID 39   // getpid()
#define SYS_GETPPID 110 // getppid()
#define SYS_EXIT_GROUP 231

/* 内存管理相关 */
#define SYS_MREMAP 25  // mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...)
#define SYS_MINCORE 27 // mincore(void *addr, size_t length, unsigned char *vec)

/* 信号处理相关 */
#define SYS_SIGACTION 13   // sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
#define SYS_SIGPROCMASK 14 // sigprocmask(int how, const sigset_t *set, sigset_t *oset)

#define SYS_ARCH_PRCTL 158
