#pragma once

#include <libs/klibc.h>
#include <task/signal.h>
#include <fs/termios.h>

struct iovec
{
    uint8_t *iov_base;
    uint64_t len;
};

struct winsize
{
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};

struct timespec
{
    long long tv_sec;
    long tv_nsec;
};

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

struct stat
{
    long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    int st_mode;
    int st_uid;
    int st_gid;
    long st_rdev;
    long long st_size;
    long st_blksize;
    unsigned long int st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    char _pad[24];
};

#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404
#define TCGETA 0x5405
#define TCSETA 0x5406
#define TCSETAW 0x5407
#define TCSETAF 0x5408
#define TCSBRK 0x5409
#define TCXONC 0x540A
#define TCFLSH 0x540B
#define TIOCEXCL 0x540C
#define TIOCNXCL 0x540D
#define TIOCSCTTY 0x540E
#define TIOCGPGRP 0x540F
#define TIOCSPGRP 0x5410
#define TIOCOUTQ 0x5411
#define TIOCSTI 0x5412
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define TIOCMGET 0x5415
#define TIOCMBIS 0x5416
#define TIOCMBIC 0x5417
#define TIOCMSET 0x5418
#define TIOCGSOFTCAR 0x5419
#define TIOCSSOFTCAR 0x541A
#define FIONREAD 0x541B
#define TIOCINQ FIONREAD
#define TIOCLINUX 0x541C
#define TIOCCONS 0x541D
#define TIOCGSERIAL 0x541E
#define TIOCSSERIAL 0x541F
#define TIOCPKT 0x5420
#define FIONBIO 0x5421
#define TIOCNOTTY 0x5422
#define TIOCSETD 0x5423
#define TIOCGETD 0x5424
#define TCSBRKP 0x5425
#define TIOCSBRK 0x5427
#define TIOCCBRK 0x5428
#define TIOCGSID 0x5429
#define TIOCGRS485 0x542E
#define TIOCSRS485 0x542F
#define TIOCGPTN 0x80045430
#define TIOCSPTLCK 0x40045431
#define TIOCGDEV 0x80045432
#define TCGETX 0x5432
#define TCSETX 0x5433
#define TCSETXF 0x5434
#define TCSETXW 0x5435
#define TIOCSIG 0x40045436
#define TIOCVHANGUP 0x5437
#define TIOCGPKT 0x80045438
#define TIOCGPTLCK 0x80045439
#define TIOCGEXCL 0x80045440
#define TIOCGPTPEER 0x5441
#define TIOCGISO7816 0x80285442
#define TIOCSISO7816 0xc0285443

#define FIONCLEX 0x5450
#define FIOCLEX 0x5451
#define FIOASYNC 0x5452
#define TIOCSERCONFIG 0x5453
#define TIOCSERGWILD 0x5454
#define TIOCSERSWILD 0x5455
#define TIOCGLCKTRMIOS 0x5456
#define TIOCSLCKTRMIOS 0x5457
#define TIOCSERGSTRUCT 0x5458
#define TIOCSERGETLSR 0x5459
#define TIOCSERGETMULTI 0x545A
#define TIOCSERSETMULTI 0x545B

#define TIOCMIWAIT 0x545C
#define TIOCGICOUNT 0x545D
#define FIOQSIZE 0x5460

#define TIOCM_LE 0x001
#define TIOCM_DTR 0x002
#define TIOCM_RTS 0x004
#define TIOCM_ST 0x008
#define TIOCM_SR 0x010
#define TIOCM_CTS 0x020
#define TIOCM_CAR 0x040
#define TIOCM_RNG 0x080
#define TIOCM_DSR 0x100
#define TIOCM_CD TIOCM_CAR
#define TIOCM_RI TIOCM_RNG
#define TIOCM_OUT1 0x2000
#define TIOCM_OUT2 0x4000
#define TIOCM_LOOP 0x8000

uint64_t sys_open(const char *name, uint64_t flags, uint64_t mode);
uint64_t sys_close(uint64_t fd);
uint64_t sys_read(uint64_t fd, void *buf, uint64_t len);
uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len);
uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence);
uint64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg);
uint64_t sys_readv(uint64_t fd, struct iovec *iovec, uint64_t count);
uint64_t sys_writev(uint64_t fd, struct iovec *iovec, uint64_t count);

uint64_t sys_getdents(uint64_t fd, uint64_t buf, uint64_t size);
uint64_t sys_chdir(const char *dirname);
uint64_t sys_getcwd(char *cwd, uint64_t size);

uint64_t sys_dup(uint64_t fd);
uint64_t sys_dup2(uint64_t fd, uint64_t newfd);

#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETSIG 10
#define F_GETSIG 11

#define F_DUPFD_CLOEXEC 1030

uint64_t sys_fcntl(uint64_t fd, uint64_t command, uint64_t arg);
int sys_pipe(int fd[2]);
uint64_t sys_stat(const char *fd, struct stat *buf);
uint64_t sys_fstat(uint64_t fd, struct stat *buf);

uint64_t sys_get_rlimit(uint64_t resource, struct rlimit *lim);
uint64_t sys_prlimit64(uint64_t pid, int resource, const struct rlimit *new_rlim, struct rlimit *old_rlim);

#define FD_SETSIZE 1024

typedef unsigned long fd_mask;

typedef struct
{
    unsigned long fds_bits[FD_SETSIZE / 8 / sizeof(long)];
} fd_set;

typedef struct
{
    sigset_t *ss;
    size_t ss_len;
} WeirdPselect6;

#define POLLIN 0x0001
#define POLLPRI 0x0002
#define POLLOUT 0x0004
#define POLLERR 0x0008
#define POLLHUP 0x0010
#define POLLNVAL 0x0020

struct pollfd
{
    int fd;
    short events;
    short revents;
};

size_t sys_poll(struct pollfd *fds, int nfds, uint64_t timeout);

size_t sys_access(char *filename, int mode);
uint64_t sys_faccessat(uint64_t dirfd, const char *pathname, uint64_t mode);
uint64_t sys_faccessat2(uint64_t dirfd, const char *pathname, uint64_t mode, uint64_t flags);
size_t sys_select(int nfds, uint8_t *read, uint8_t *write, uint8_t *except, struct timeval *timeout);
uint64_t sys_pselect6(uint64_t nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timespec *timeout, WeirdPselect6 *weirdPselect6);

uint64_t sys_link(const char *old, const char *new);
uint64_t sys_readlink(char *path, char *buf, uint64_t size);

typedef union epoll_data
{
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event
{
    uint32_t events;
    epoll_data_t data;
}
#ifdef __x86_64__
__attribute__((__packed__))
#endif
;

typedef struct epoll_watch
{
    struct epoll_watch *next;

    vfs_node_t fd;
    int watchEvents;

    uint64_t userlandData;
} epoll_watch_t;

typedef struct epoll
{
    bool lock;

    struct epoll *next;

    epoll_watch_t *firstEpollWatch;

    uint64_t reference_count;
} epoll_t;

uint32_t poll_to_epoll_comp(uint32_t poll_events);
uint32_t epoll_to_poll_comp(uint32_t epoll_events);

#define EPOLLIN 0x001
#define EPOLLPRI 0x002
#define EPOLLOUT 0x004
#define EPOLLRDNORM 0x040
#define EPOLLNVAL 0x020
#define EPOLLRDBAND 0x080
#define EPOLLWRNORM 0x100
#define EPOLLWRBAND 0x200
#define EPOLLMSG 0x400
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLRDHUP 0x2000
#define EPOLLEXCLUSIVE (1U << 28)
#define EPOLLWAKEUP (1U << 29)
#define EPOLLONESHOT (1U << 30)
#define EPOLLET (1U << 31)

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

uint64_t sys_epoll_create(int size);
uint64_t sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
uint64_t sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
uint64_t sys_epoll_pwait(int epfd, struct epoll_event *events,
                         int maxevents, int timeout, sigset_t *sigmask,
                         size_t sigsetsize);
uint64_t sys_epoll_create1(int flags);

#define EFD_CLOEXEC 02000000
#define EFD_NONBLOCK 04000
#define EFD_SEMAPHORE 00000001

typedef struct eventfd
{
    uint64_t count;
    int flags;
} eventfd_t;

uint64_t sys_eventfd2(uint64_t initial_val, uint64_t flags);

#define SIGNALFD_IOC_MASK 0x53010008

uint64_t sys_signalfd4(int ufd, const sigset_t *mask, size_t sizemask, int flags);
uint64_t sys_signalfd(int ufd, const sigset_t *mask, size_t sizemask);

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

#define L_SET 0
#define L_INCR 1
#define L_XTND 2

#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2

uint64_t sys_flock(int fd, uint64_t cmd);

uint64_t sys_mkdir(const char *name, uint64_t mode);

void wake_blocked_tasks(task_block_list_t *head);
