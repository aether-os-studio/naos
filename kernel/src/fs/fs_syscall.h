#pragma once

#include <libs/klibc.h>
#include <fs/termios.h>
#include <fs/vfs/pipe.h>
#include <fs/vfs/vfs.h>
#include <fs/vfs/fcntl.h>
#include <task/task.h>
#include <libs/mutex.h>

char *at_resolve_pathname(int dirfd, char *pathname);
char *at_resolve_pathname_fullpath(int dirfd, char *pathname);

struct iovec {
    uint8_t *iov_base;
    uint64_t len;
};

struct winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};

/*
 * These are the fs-independent mount-flags: up to 32 flags are supported
 *
 * Usage of these is restricted within the kernel to core mount(2) code and
 * callers of sys_mount() only.  Filesystems should be using the SB_*
 * equivalent instead.
 */
#define MS_RDONLY 1        /* Mount read-only */
#define MS_NOSUID 2        /* Ignore suid and sgid bits */
#define MS_NODEV 4         /* Disallow access to device special files */
#define MS_NOEXEC 8        /* Disallow program execution */
#define MS_SYNCHRONOUS 16  /* Writes are synced at once */
#define MS_REMOUNT 32      /* Alter flags of a mounted FS */
#define MS_MANDLOCK 64     /* Allow mandatory locks on an FS */
#define MS_DIRSYNC 128     /* Directory modifications are synchronous */
#define MS_NOSYMFOLLOW 256 /* Do not follow symlinks */
#define MS_NOATIME 1024    /* Do not update access times. */
#define MS_NODIRATIME 2048 /* Do not update directory access times */
#define MS_BIND 4096
#define MS_MOVE 8192
#define MS_REC 16384
#define MS_VERBOSE                                                             \
    32768 /* War is peace. Verbosity is silence.                               \
             MS_VERBOSE is deprecated. */
#define MS_SILENT 32768
#define MS_POSIXACL (1 << 16)    /* VFS does not apply the umask */
#define MS_UNBINDABLE (1 << 17)  /* change to unbindable */
#define MS_PRIVATE (1 << 18)     /* change to private */
#define MS_SLAVE (1 << 19)       /* change to slave */
#define MS_SHARED (1 << 20)      /* change to shared */
#define MS_RELATIME (1 << 21)    /* Update atime relative to mtime/ctime. */
#define MS_KERNMOUNT (1 << 22)   /* this is a kern_mount call */
#define MS_I_VERSION (1 << 23)   /* Update inode I_version field */
#define MS_STRICTATIME (1 << 24) /* Always perform atime updates */
#define MS_LAZYTIME (1 << 25)    /* Update the on-disk [acm]times lazily */

/* These sb flags are internal to the kernel */
#define MS_SUBMOUNT (1 << 26)
#define MS_NOREMOTELOCK (1 << 27)
#define MS_NOSEC (1 << 28)
#define MS_BORN (1 << 29)
#define MS_ACTIVE (1 << 30)
#define MS_NOUSER (1 << 31)

#define SPECIAL_FD 0x2025

#define CLOSE_RANGE_UNSHARE (1U << 1)
#define CLOSE_RANGE_CLOEXEC (1U << 2)

uint64_t sys_mount(char *dev_name, char *dir_name, char *type, uint64_t flags,
                   void *data);
uint64_t sys_umount2(const char *target, uint64_t flags);

uint64_t sys_open(const char *name, uint64_t flags, uint64_t mode);
uint64_t sys_openat(uint64_t dirfd, const char *name, uint64_t flags,
                    uint64_t mode);
uint64_t sys_name_to_handle_at(int dfd, const char *name,
                               struct file_handle *handle, int *mnt_id,
                               int flag);
uint64_t sys_open_by_handle_at(int mountdirfd, struct file_handle *handle,
                               int flags);
uint64_t sys_inotify_init();
uint64_t sys_inotify_init1(uint64_t flags);
uint64_t sys_inotify_add_watch(uint64_t notifyfd, const char *path,
                               uint64_t mask);
uint64_t sys_inotify_rm_watch(uint64_t watchfd, uint64_t mask);

uint64_t sys_fsync(uint64_t fd);
uint64_t sys_close(uint64_t fd);
uint64_t sys_close_range(uint64_t fd, uint64_t maxfd, uint64_t flags);
uint64_t sys_copy_file_range(uint64_t fd_in, int *offset_in, uint64_t fd_out,
                             int *offset_out, uint64_t len, uint64_t flags);
uint64_t sys_read(uint64_t fd, void *buf, uint64_t len);
uint64_t sys_write(uint64_t fd, const void *buf, uint64_t len);
uint64_t sys_sendfile(uint64_t out_fd, uint64_t in_fd, int *offset_ptr,
                      size_t count);
uint64_t sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence);
uint64_t sys_ioctl(uint64_t fd, uint64_t cmd, uint64_t arg);
uint64_t sys_readv(uint64_t fd, struct iovec *iovec, uint64_t count);
uint64_t sys_writev(uint64_t fd, struct iovec *iovec, uint64_t count);

uint64_t sys_getdents(uint64_t fd, uint64_t buf, uint64_t size);
uint64_t sys_chdir(const char *dirname);
uint64_t sys_chroot(const char *dname);
uint64_t sys_getcwd(char *cwd, uint64_t size);

uint64_t sys_dup(uint64_t fd);
uint64_t sys_dup2(uint64_t fd, uint64_t newfd);
uint64_t sys_dup3(uint64_t oldfd, uint64_t newfd, uint64_t flags);

#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETSIG 10
#define F_GETSIG 11

#define F_DUPFD_CLOEXEC 1030
#define F_LINUX_SPECIFIC_BASE 1024

#define F_SETLEASE (F_LINUX_SPECIFIC_BASE + 0)
#define F_GETLEASE (F_LINUX_SPECIFIC_BASE + 1)

#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_GET_RW_HINT (F_LINUX_SPECIFIC_BASE + 11)
#define F_SET_RW_HINT (F_LINUX_SPECIFIC_BASE + 12)
#define F_GET_FILE_RW_HINT (F_LINUX_SPECIFIC_BASE + 13)
#define F_SET_FILE_RW_HINT (F_LINUX_SPECIFIC_BASE + 14)

#define F_SEAL_SEAL 0x0001   /* 防止后续seal操作 */
#define F_SEAL_SHRINK 0x0002 /* 禁止缩小文件 */
#define F_SEAL_GROW 0x0004   /* 禁止增大文件 */
#define F_SEAL_WRITE 0x0008  /* 禁止写操作 */

#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38

uint64_t sys_fcntl(uint64_t fd, uint64_t command, uint64_t arg);
uint64_t sys_pipe(int fd[2], uint64_t flags);
uint64_t sys_stat(const char *fd, struct stat *buf);
uint64_t sys_fstat(uint64_t fd, struct stat *buf);
uint64_t sys_newfstatat(uint64_t dirfd, const char *pathname, struct stat *buf,
                        uint64_t flags);

struct statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};

struct statx {
    /* 0x00 */
    uint32_t stx_mask;       /* What results were written [uncond] */
    uint32_t stx_blksize;    /* Preferred general I/O size [uncond] */
    uint64_t stx_attributes; /* Flags conveying information about the file
                                [uncond] */
    /* 0x10 */
    uint32_t stx_nlink; /* Number of hard links */
    uint32_t stx_uid;   /* User ID of owner */
    uint32_t stx_gid;   /* Group ID of owner */
    uint16_t stx_mode;  /* File mode */
    uint16_t __spare0[1];
    /* 0x20 */
    uint64_t stx_ino;             /* Inode number */
    uint64_t stx_size;            /* File size */
    uint64_t stx_blocks;          /* Number of 512-byte blocks allocated */
    uint64_t stx_attributes_mask; /* Mask to show what's supported in
                                     stx_attributes */
    /* 0x40 */
    struct statx_timestamp stx_atime; /* Last access time */
    struct statx_timestamp stx_btime; /* File creation time */
    struct statx_timestamp stx_ctime; /* Last attribute change time */
    struct statx_timestamp stx_mtime; /* Last data modification time */
    /* 0x80 */
    uint32_t stx_rdev_major; /* Device ID of special file [if bdev/cdev] */
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major; /* ID of device containing file [uncond] */
    uint32_t stx_dev_minor;
    /* 0x90 */
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;    /* Memory buffer alignment for direct I/O */
    uint32_t stx_dio_offset_align; /* File offset alignment for direct I/O */
    /* 0xa0 */
    uint64_t __spare3[12]; /* Spare space for future expansion */
                           /* 0x100 */
};

uint64_t sys_statx(uint64_t dirfd, const char *pathname, uint64_t flags,
                   uint64_t mask, struct statx *buf);

#define RLIMIT_CPU 0
#define RLIMIT_FSIZE 1
#define RLIMIT_DATA 2
#define RLIMIT_STACK 3
#define RLIMIT_CORE 4
#define RLIMIT_RSS 5
#define RLIMIT_NPROC 6
#define RLIMIT_NOFILE 7
#define RLIMIT_MEMLOCK 8
#define RLIMIT_AS 9
#define RLIMIT_LOCKS 10
#define RLIMIT_SIGPENDING 11
#define RLIMIT_MSGQUEUE 12
#define RLIMIT_NICE 13
#define RLIMIT_RTPRIO 14
#define RLIMIT_RTTIME 15
#define RLIMIT_NLIMITS 16

uint64_t sys_get_rlimit(uint64_t resource, struct rlimit *lim);
uint64_t sys_prlimit64(uint64_t pid, int resource,
                       const struct rlimit *new_rlim, struct rlimit *old_rlim);

#define FD_SETSIZE 1024

typedef unsigned long fd_mask;

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / 8 / sizeof(long)];
} fd_set;

typedef struct {
    sigset_t *ss;
    size_t ss_len;
} WeirdPselect6;

struct pollfd {
    int fd;
    short events;
    short revents;
};

size_t sys_poll(struct pollfd *fds, int nfds, uint64_t timeout);
uint64_t sys_ppoll(struct pollfd *fds, uint64_t nfds,
                   const struct timespec *timeout_ts, const sigset_t *sigmask,
                   size_t sigsetsize);

size_t sys_access(char *filename, int mode);
uint64_t sys_faccessat(uint64_t dirfd, const char *pathname, uint64_t mode);
uint64_t sys_faccessat2(uint64_t dirfd, const char *pathname, uint64_t mode,
                        uint64_t flags);
size_t sys_select(int nfds, uint8_t *read, uint8_t *write, uint8_t *except,
                  struct timeval *timeout);
uint64_t sys_pselect6(uint64_t nfds, fd_set *readfds, fd_set *writefds,
                      fd_set *exceptfds, struct timespec *timeout,
                      WeirdPselect6 *weirdPselect6);

uint64_t sys_link(const char *old, const char *new);
uint64_t sys_readlink(char *path, char *buf, uint64_t size);
uint64_t sys_readlinkat(int dfd, char *path, char *buf, uint64_t size);

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t events;
    epoll_data_t data;
}
#ifdef __x86_64__
__attribute__((__packed__))
#endif
;

typedef struct epoll_watch {
    struct llist_header node;
    vfs_node_t file;
    uint32_t events;
    uint64_t data;
    bool edge_trigger;
    uint32_t last_events;
} epoll_watch_t;

typedef struct epoll {
    struct llist_header watches;
    mutex_t lock;
} epoll_t;

uint32_t poll_to_epoll_comp(uint32_t poll_events);
uint32_t epoll_to_poll_comp(uint32_t epoll_events);

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

uint64_t sys_epoll_create(int size);
uint64_t sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                        int timeout);
uint64_t sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
uint64_t sys_epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                         int timeout, sigset_t *sigmask, size_t sigsetsize);
uint64_t sys_epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                          struct timespec *timeout, sigset_t *sigmask,
                          size_t sigsetsize);
uint64_t sys_epoll_create1(int flags);

#define EFD_CLOEXEC 02000000
#define EFD_NONBLOCK 04000
#define EFD_SEMAPHORE 00000001

typedef struct eventfd {
    vfs_node_t node;
    uint64_t count;
    int flags;
} eventfd_t;

uint64_t sys_eventfd2(uint64_t initial_val, uint64_t flags);

#define SIGNALFD_IOC_MASK 0x53010008

uint64_t sys_signalfd4(int ufd, const sigset_t *mask, size_t sizemask,
                       int flags);
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
uint64_t sys_mkdirat(int dfd, const char *name, uint64_t mode);

uint64_t sys_link(const char *name, const char *target_name);
uint64_t sys_symlink(const char *name, const char *target_name);
uint64_t sys_symlinkat(const char *name, int dfd, const char *new);
uint64_t sys_mknod(const char *name, uint16_t umode, int dev);
uint64_t sys_mknodat(uint64_t fd, const char *path_user, uint16_t umode,
                     int dev);

uint64_t sys_chmod(const char *name, uint16_t mode);
uint64_t sys_fchmod(int fd, uint16_t mode);
uint64_t sys_fchmodat(int dfd, const char *name, uint16_t mode);
uint64_t sys_fchmodat2(int dfd, const char *name, uint16_t mode, int flags);

uint64_t sys_chown(const char *filename, uint64_t uid, uint64_t gid);
uint64_t sys_fchown(int fd, uint64_t uid, uint64_t gid);
uint64_t sys_fchownat(int dfd, const char *filename, uint64_t uid, uint64_t gid,
                      int flags);

uint64_t sys_rename(const char *old, const char *new);
uint64_t sys_renameat(uint64_t oldfd, const char *old, uint64_t newfd,
                      const char *new);
uint64_t sys_renameat2(uint64_t oldfd, const char *old, uint64_t newfd,
                       const char *new, uint64_t flags);

uint64_t sys_fchdir(uint64_t fd);

uint64_t sys_rmdir(const char *name);
uint64_t sys_unlink(const char *name);
uint64_t sys_unlinkat(uint64_t dirfd, const char *name, uint64_t flags);

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_MONOTONIC_COARSE 6
#define CLOCK_BOOTTIME 7
#define CLOCK_REALTIME_ALARM 8
#define CLOCK_BOOTTIME_ALARM 9
#define CLOCK_SGI_CYCLE 10
#define CLOCK_TAI 11

typedef struct {
    kernel_timer_t timer;
    uint64_t count;
    int flags;
    vfs_node_t node;
} timerfd_t;

#define TFD_TIMER_ABSTIME (1 << 0)
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)

uint64_t sys_timerfd_create(int clockid, int flags);
uint64_t sys_timerfd_settime(int fd, int flags,
                             const struct itimerval *new_value,
                             struct itimerval *old_v);

uint64_t sys_memfd_create(const char *name, unsigned int flags);

typedef struct {
    int val[2];
} __kernel_fsid_t;

struct statfs {
    uint64_t f_type;
    uint64_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    __kernel_fsid_t f_fsid;
    uint64_t f_namelen;
    uint64_t f_frsize;
    uint64_t f_flags;
    uint64_t f_spare[4];
};

enum fsconfig_command {
    FSCONFIG_SET_FLAG = 0, /* Set parameter, supplying no value */
#define FSCONFIG_SET_FLAG FSCONFIG_SET_FLAG
    FSCONFIG_SET_STRING = 1, /* Set parameter, supplying a string value */
#define FSCONFIG_SET_STRING FSCONFIG_SET_STRING
    FSCONFIG_SET_BINARY = 2, /* Set parameter, supplying a binary blob value */
#define FSCONFIG_SET_BINARY FSCONFIG_SET_BINARY
    FSCONFIG_SET_PATH = 3, /* Set parameter, supplying an object by path */
#define FSCONFIG_SET_PATH FSCONFIG_SET_PATH
    FSCONFIG_SET_PATH_EMPTY =
        4, /* Set parameter, supplying an object by (empty) path */
#define FSCONFIG_SET_PATH_EMPTY FSCONFIG_SET_PATH_EMPTY
    FSCONFIG_SET_FD = 5, /* Set parameter, supplying an object by fd */
#define FSCONFIG_SET_FD FSCONFIG_SET_FD
    FSCONFIG_CMD_CREATE = 6, /* Invoke superblock creation */
#define FSCONFIG_CMD_CREATE FSCONFIG_CMD_CREATE
    FSCONFIG_CMD_RECONFIGURE = 7, /* Invoke superblock reconfiguration */
#define FSCONFIG_CMD_RECONFIGURE FSCONFIG_CMD_RECONFIGURE
    FSCONFIG_CMD_CREATE_EXCL =
        8, /* Create new superblock, fail if reusing existing superblock */
#define FSCONFIG_CMD_CREATE_EXCL FSCONFIG_CMD_CREATE_EXCL
};

/* FSMOUNT flags */
#define FSMOUNT_CLOEXEC 0x00000001

/* Mount attributes for fsmount */
#define MOUNT_ATTR_RDONLY 0x00000001
#define MOUNT_ATTR_NOSUID 0x00000002
#define MOUNT_ATTR_NODEV 0x00000004
#define MOUNT_ATTR_NOEXEC 0x00000008
#define MOUNT_ATTR_RELATIME 0x00000000
#define MOUNT_ATTR_NOATIME 0x00000010
#define MOUNT_ATTR_STRICTATIME 0x00000020
#define MOUNT_ATTR_NODIRATIME 0x00000080
#define MOUNT_ATTR_NOSYMFOLLOW 0x00200000

/* move_mount flags */
#define MOVE_MOUNT_F_SYMLINKS 0x00000001
#define MOVE_MOUNT_F_AUTOMOUNTS 0x00000002
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define MOVE_MOUNT_T_SYMLINKS 0x00000010
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#define MOVE_MOUNT_SET_GROUP 0x00000100
#define MOVE_MOUNT_BENEATH 0x00000200

uint64_t sys_fsopen(const char *fsname, unsigned int flags);
uint64_t sys_statfs(const char *fsname, struct statfs *buf);
uint64_t sys_fstatfs(int fd, struct statfs *buf);
uint64_t sys_fsconfig(int fd, uint32_t cmd, const char *key, const void *value,
                      int aux);
uint64_t sys_fsmount(int fd, uint32_t flags, uint32_t attr_flags);
uint64_t sys_move_mount(int from_dfd, const char *from_pathname_user,
                        int to_dfd, const char *to_pathname_user,
                        uint32_t flags);

uint64_t sys_truncate(const char *path, uint64_t length);
uint64_t sys_ftruncate(int fd, uint64_t length);
uint64_t sys_fallocate(int fd, int mode, uint64_t offset, uint64_t len);

uint64_t sys_fadvise64(int fd, uint64_t offset, uint64_t len, int advice);

uint64_t sys_utimensat(int dfd, const char *pathname, struct timespec *utimes,
                       int flags);
uint64_t sys_futimesat(int dfd, const char *pathname, struct timeval *utimes);

static inline uint64_t sys_pwrite64(int fd, const void *buf, size_t count,
                                    uint64_t offset) {
    sys_lseek(fd, offset, SEEK_SET);
    return sys_write(fd, buf, count);
}

static inline uint64_t sys_pread64(int fd, void *buf, size_t count,
                                   uint64_t offset) {
    sys_lseek(fd, offset, SEEK_SET);
    return sys_read(fd, buf, count);
}

struct sysinfo {
    int64_t uptime;     /* Seconds since boot */
    uint64_t loads[3];  /* 1, 5, and 15 minute load averages */
    uint64_t totalram;  /* Total usable main memory size */
    uint64_t freeram;   /* Available memory size */
    uint64_t sharedram; /* Amount of shared memory */
    uint64_t bufferram; /* Memory used by buffers */
    uint64_t totalswap; /* Total swap space size */
    uint64_t freeswap;  /* swap space still available */
    uint16_t procs;     /* Number of current processes */
    uint16_t pad;       /* Explicit padding for m68k */
    uint64_t totalhigh; /* Total high memory size */
    uint64_t freehigh;  /* Available high memory size */
    uint32_t mem_unit;  /* Memory unit size in bytes */
    char _f[20 - 2 * sizeof(uint64_t) -
            sizeof(uint32_t)]; /* Padding: libc5 uses this.. */
};

uint64_t sys_sysinfo(struct sysinfo *info);
