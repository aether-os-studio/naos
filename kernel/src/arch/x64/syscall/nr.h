#pragma once

#include <stdint.h>

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
#define SYS_DUP 32
#define SYS_DUP2 33
#define SYS_IOCTL 16 // ioctl(int fd, sint cmd, int arg)
#define SYS_GETDENTS64 217
#define SYS_PIPE 22
#define SYS_PIPE2 293
#define SYS_CHDIR 80
#define SYS_GETCWD 79
#define SYS_FCNTL 72
#define SYS_ACCESS 21
#define SYS_FACCESSAT 269
#define SYS_PSELECT6 270

#define SYS_SOCKET 41
#define SYS_CONNECT 42
#define SYS_ACCEPT 43
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_GETSOCKNAME 51
#define SYS_GETPEERNAME 52
#define SYS_SOCKETPAIR 53
#define SYS_GETSOCKOPT 55
#define SYS_SENDTO 44
#define SYS_RECVFROM 45
#define SYS_RECVMSG 47

/* 进程管理相关 */
#define SYS_FORK 57   // fork()
#define SYS_VFORK 58  // vfork()
#define SYS_EXECVE 59 // execve(const char *pathname, char *const argv[], char *const envp[])
#define SYS_EXIT 60   // exit(int status)
#define SYS_WAIT4 61  // wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage)
#define SYS_KILL 62   // kill(pid_t pid, int sig)
#define SYS_UNAME 63
#define SYS_GETPID 39   // getpid()
#define SYS_GETUID 102  // getuid()
#define SYS_GETGID 104  // getgid()
#define SYS_GETEUID 107 // geteuid()
#define SYS_GETEGID 108 // getegid()
#define SYS_SETPGID 109 // setpgid(int pid, int64_t pgid)
#define SYS_GETPGID 121 // getpgid()
#define SYS_GETPPID 110 // getppid()
#define SYS_GETTID 186
#define SYS_FUTEX 202
#define SYS_EXIT_GROUP 231
#define SYS_GETRLIMIT 97
#define SYS_PRLIMIT64 302

/* 内存管理相关 */
#define SYS_MINCORE 27 // mincore(void *addr, size_t length, unsigned char *vec)

/* 信号处理相关 */
#define SYS_SIGACTION 13   // sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
#define SYS_SIGPROCMASK 14 // sigprocmask(int how, const sigset_t *set, sigset_t *oset)
#define SYS_SIGRETURN 15
#define SYS_SIGALTSTACK 131

#define SYS_ARCH_PRCTL 158

#define SYS_SIGNAL 350
#define SYS_SETMASK 351
#define SYS_CLOCK_GETTIME 228

#define SYS_SET_TID_ADDRESS 218

typedef struct fb_info
{
    uint64_t fb_addr;
    uint64_t width;
    uint64_t height;
    uint16_t bpp;
    uint64_t red_mask_size;
    uint64_t red_mask_shift;
    uint64_t blue_mask_size;
    uint64_t blue_mask_shift;
    uint64_t green_mask_size;
    uint64_t green_mask_shift;
} fb_info_t;

struct rlimit
{
    size_t rlim_cur;
    size_t rlim_max;
};

#define FB_IOCTL_GETINFO 1
