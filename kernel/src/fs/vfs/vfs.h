#pragma once

#include <libs/klibc.h>
#include <libs/llist.h>
#include <fs/vfs/fcntl.h>
#include <fs/vfs/utils.h>

// * 所有时间请使用 GMT 时间 *

// 读写时请 padding 到 PAGE_SIZE 的整数倍
#define FILE_BLKSIZE PAGE_SIZE

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

enum {
    file_none = 0x0001UL,    // 普通文件
    file_dir = 0x0002UL,     // 文件夹
    file_symlink = 0x0004UL, // 符号链接
    file_block = 0x00008UL,  // 块设备，如硬盘
    file_stream = 0x0010UL,  // 流式设备，如终端
    file_pipe = 0x0020UL,    // 管道设备
    file_socket = 0x0040UL,  // 套接字设备
    file_epoll = 0x0080UL,   // epoll 设备
    file_fifo = 0x0100UL,    // fifo 设备
};

typedef struct vfs_node *vfs_node_t;
struct task;
typedef struct task task_t;

typedef struct fd {
    vfs_node_t node;
    uint64_t offset;
    uint64_t flags;
    bool close_on_exec;
} fd_t;

typedef struct vfs_poll_wait {
    struct llist_header node;
    task_t *task;
    vfs_node_t watch_node;
    uint32_t events;
    volatile uint32_t revents;
    volatile bool armed;
} vfs_poll_wait_t;

typedef int (*vfs_mount_t)(uint64_t dev, vfs_node_t node);
typedef void (*vfs_unmount_t)(vfs_node_t node);
typedef int (*vfs_remount_t)(vfs_node_t old, vfs_node_t node);

/**
 *\brief 打开一个文件
 *
 *\param parent   父目录句柄
 *\param name     文件名
 *\param node     文件节点
 */
typedef void (*vfs_open_t)(vfs_node_t parent, const char *name,
                           vfs_node_t node);

/**
 *\brief 关闭一个文件
 *
 *\param current  当前文件句柄
 */
typedef bool (*vfs_close_t)(vfs_node_t node);

/**
 *\brief 重设文件大小
 *
 *\param current  当前文件句柄
 *\param size     新的大小
 */
typedef void (*vfs_resize_t)(vfs_node_t node, uint64_t size);

/**
 *\brief 写入一个文件
 *
 *\param file     文件句柄
 *\param addr     写入的数据
 *\param offset   写入的偏移
 *\param size     写入的大小
 */
typedef ssize_t (*vfs_write_t)(fd_t *fd, const void *addr, size_t offset,
                               size_t size);

/**
 *\brief 读取一个文件
 *
 *\param file     文件句柄
 *\param addr     读取的数据
 *\param offset   读取的偏移
 *\param size     读取的大小
 */
typedef ssize_t (*vfs_read_t)(fd_t *fd, void *addr, size_t offset, size_t size);

typedef ssize_t (*vfs_readlink_t)(vfs_node_t node, void *addr, size_t offset,
                                  size_t size);

/**
 *\brief 获取文件信息
 *
 *\param file     文件句柄
 *\param node     文件节点
 */
typedef int (*vfs_stat_t)(vfs_node_t node);

// 创建一个文件或文件夹
typedef int (*vfs_mk_t)(vfs_node_t parent, const char *name, vfs_node_t node);

typedef int (*vfs_mknod_t)(vfs_node_t parent, const char *name, vfs_node_t node,
                           uint16_t mode, int dev);

typedef int (*vfs_chmod_t)(vfs_node_t node, uint16_t mode);
typedef int (*vfs_chown_t)(vfs_node_t node, uint64_t uid, uint64_t gid);

typedef int (*vfs_del_t)(vfs_node_t parent, vfs_node_t node);

typedef int (*vfs_rename_t)(vfs_node_t node, const char *new);

// 创建一个文件或文件夹
typedef int (*vfs_ioctl_t)(vfs_node_t node, ssize_t cmd, ssize_t arg);

// 映射文件从 offset 开始的 size 大小
typedef void *(*vfs_mapfile_t)(fd_t *fd, void *addr, size_t offset, size_t size,
                               size_t prot, size_t flags);

typedef int (*vfs_poll_t)(vfs_node_t node, size_t events);

typedef void (*vfs_free_handle_t)(vfs_node_t node);

uint32_t poll_to_epoll_comp(uint32_t poll_events);
uint32_t epoll_to_poll_comp(uint32_t epoll_events);

void vfs_generic_free_handle(vfs_node_t node);

typedef struct vfs_super_operations {
    vfs_mount_t mount;
    vfs_unmount_t unmount;
    vfs_remount_t remount;

    int (*sync_fs)(vfs_node_t root);
    int (*freeze_fs)(vfs_node_t root);
    int (*thaw_fs)(vfs_node_t root);
} vfs_super_operations_t;

typedef struct vfs_inode_operations {
    vfs_open_t open;
    vfs_readlink_t readlink;
    vfs_mk_t mkdir;
    vfs_mk_t mkfile;
    vfs_mk_t link;
    vfs_mk_t symlink;
    vfs_mknod_t mknod;
    vfs_chmod_t chmod;
    vfs_chown_t chown;
    vfs_del_t delete;
    vfs_rename_t rename;
    vfs_stat_t stat;
    vfs_resize_t resize;
} vfs_inode_operations_t;

typedef struct vfs_file_operations {
    vfs_close_t close;
    vfs_read_t read;
    vfs_write_t write;
    vfs_mapfile_t map;
    vfs_ioctl_t ioctl;
    vfs_poll_t poll;
    vfs_free_handle_t free_handle;
} vfs_file_operations_t;

typedef struct vfs_operations {
    union {
        vfs_super_operations_t super_ops;
        struct {
            vfs_mount_t mount;
            vfs_unmount_t unmount;
            vfs_remount_t remount;
            int (*sync_fs)(vfs_node_t root);
            int (*freeze_fs)(vfs_node_t root);
            int (*thaw_fs)(vfs_node_t root);
        };
    };

    union {
        vfs_inode_operations_t inode_ops;
        struct {
            vfs_open_t open;
            vfs_readlink_t readlink;
            vfs_mk_t mkdir;
            vfs_mk_t mkfile;
            vfs_mk_t link;
            vfs_mk_t symlink;
            vfs_mknod_t mknod;
            vfs_chmod_t chmod;
            vfs_chown_t chown;
            vfs_del_t delete;
            vfs_rename_t rename;
            vfs_stat_t stat;
            vfs_resize_t resize;
        };
    };

    union {
        vfs_file_operations_t file_ops;
        struct {
            vfs_close_t close;
            vfs_read_t read;
            vfs_write_t write;
            vfs_mapfile_t map;
            vfs_ioctl_t ioctl;
            vfs_poll_t poll;
            vfs_free_handle_t free_handle;
        };
    };
} vfs_operations_t;

enum {
    TMPFS_DEV_MAJOR = 240,
    RAMFS_DEV_MAJOR,
    DEVFS_DEV_MAJOR,
    PROCFS_DEV_MAJOR,
    SYSFS_DEV_MAJOR,
    CGROUPFS_DEV_MAJOR,
};

#define FS_FLAGS_HIDDEN (1UL << 0)
#define FS_FLAGS_VIRTUAL (1UL << 1)
#define FS_FLAGS_NEED_OPEN (1UL << 2)

typedef struct fs {
    const char *name;
    uint64_t magic;
    const vfs_operations_t *ops;
    uint64_t flags;
} fs_t;

extern fs_t *all_fs[256];

typedef struct flock {
    volatile uint64_t l_pid;
    volatile uint64_t l_type;
    volatile uint64_t lock;
} flock_t;

#define VFS_NODE_FLAGS_OPENED (1UL << 0)
#define VFS_NODE_FLAGS_DELETED (1UL << 1)
#define VFS_NODE_FLAGS_FREE_AFTER_USE (1UL << 2)
#define VFS_NODE_FLAGS_DIRTY_METADATA (1UL << 3)
#define VFS_NODE_FLAGS_DIRTY_CHILDREN (1UL << 4)

struct vfs_node {
    vfs_node_t parent;                   // 父目录
    uint64_t flags;                      // 标志
    uint64_t dev;                        // 设备号
    uint64_t rdev;                       // 真实设备号
    char *name;                          // 名称
    uint64_t inode;                      // 节点号
    uint64_t realsize;                   // 项目真实占用的空间 (可选)
    uint64_t size;                       // 文件大小或若是文件夹则填0
    uint64_t blksz;                      // 块大小
    uint64_t createtime;                 // 创建时间
    uint64_t readtime;                   // 最后读取时间
    uint64_t writetime;                  // 最后写入时间
    uint32_t owner;                      // 所有者
    uint32_t group;                      // 所有组
    uint32_t type;                       // 类型
    uint32_t fsid;                       // 文件系统的 id
    void *handle;                        // 操作文件的句柄
    flock_t lock;                        // 锁
    struct llist_header node;            // 所有vfs_node的链表
    struct llist_header childs;          // 子目录和子文件
    struct llist_header node_for_childs; // 为子目录和子文件添加的节点
    vfs_node_t root;                     // 根目录
    int refcount;                        // 引用计数
    uint16_t mode;                       // 模式
    uint32_t rw_hint;                    // 读写提示
    spinlock_t poll_waiters_lock;        // poll 等待队列锁
    struct llist_header poll_waiters;    // poll 等待队列
    uint64_t poll_seq_in;                // 可读相关事件变化序号
    uint64_t poll_seq_out;               // 可写相关事件变化序号
    uint64_t poll_seq_pri;               // 紧急数据事件变化序号
    uint64_t i_version;                  // 数据变更版本
};

struct mount_point {
    struct llist_header node;
    fs_t *fs;
    vfs_node_t dir;
    char *devname;
};

#define IN_ACCESS 0x1
#define IN_ATTRIB 0x4
#define IN_CLOSE_WRITE 0x8
#define IN_CLOSE_NOWRITE 0x10
#define IN_CREATE 0x100
#define IN_DELETE 0x200
#define IN_DELETE_SELF 0x400
#define IN_MODIFY 0x2
#define IN_MOVE_SELF 0x800
#define IN_MOVED_FROM 0x40
#define IN_MOVED_TO 0x80
#define IN_OPEN 0x20
#define IN_MOVE (IN_MOVED_FROM | IN_MOVED_TO)
#define IN_CLOSE (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)
#define IN_DONT_FOLLOW 0x2000000
#define IN_EXCL_UNLINK 0x4000000
#define IN_MASK_ADD 0x20000000
#define IN_ONESHOT 0x80000000
#define IN_ONLYDIR 0x1000000
#define IN_IGNORED 0x8000
#define IN_ISDIR 0x40000000
#define IN_Q_OVERFLOW 0x4000
#define IN_UNMOUNT 0x2000

struct vfs_notify_event {
    struct llist_header node;
    vfs_node_t changed_node;
    uint64_t mask;
};

struct notifyfs_handle;
typedef struct notifyfs_handle notifyfs_handle_t;

typedef struct notifyfs_watch {
    uint64_t wd;
    vfs_node_t watch_node;
    notifyfs_handle_t *owner;
    uint64_t mask;
    struct llist_header node;
    struct llist_header all_watches_node;
    spinlock_t events_lock;
    struct llist_header events;
} notifyfs_watch_t;

struct notifyfs_handle {
    struct llist_header watches;
    vfs_node_t node;
};

void vfs_on_new_event(vfs_node_t node, uint64_t mask);
void vfs_mark_dirty(vfs_node_t node, uint64_t dirty_flags);

void vfs_poll_wait_init(vfs_poll_wait_t *wait, task_t *task, uint32_t events);
int vfs_poll_wait_arm(vfs_node_t node, vfs_poll_wait_t *wait);
void vfs_poll_wait_disarm(vfs_poll_wait_t *wait);
int vfs_poll_wait_sleep(vfs_node_t node, vfs_poll_wait_t *wait,
                        int64_t timeout_ns, const char *reason);
void vfs_poll_notify(vfs_node_t node, uint32_t events);

void vfs_add_mount_point(vfs_node_t dir, char *devname);
void vfs_delete_mount_point_by_dir(vfs_node_t dir);

extern vfs_node_t rootdir; // vfs 根目录

vfs_node_t vfs_node_alloc(vfs_node_t parent, const char *name);
void vfs_free(vfs_node_t vfs);
void vfs_free_child(vfs_node_t vfs);
// 一定要记得手动设置一下child的type
vfs_node_t vfs_child_find(vfs_node_t parent, const char *name);
vfs_node_t vfs_child_append(vfs_node_t parent, const char *name, void *handle);

bool vfs_init();

/**
 *\brief 注册一个文件系统
 *
 *\param fs      文件系统
 *\return 文件系统 id
 */
int vfs_regist(fs_t *fs);

#define PATH_MAX 4096    // 路径最大长度
#define FILENAME_MAX 256 // 文件名最大长度

vfs_node_t vfs_open_at(vfs_node_t start, const char *_path, uint64_t flags);

vfs_node_t vfs_open(const char *_path, uint64_t flags);

vfs_node_t vfs_find_node_by_inode(uint64_t inode);

/**
 *\brief 创建文件夹
 *
 *\param name     文件夹名
 *\return 0 成功，-1 失败
 */
int vfs_mkdir(const char *name);
/**
 *\brief 创建文件
 *
 *\param name     文件名
 *\return 0 成功，-1 失败
 */
int vfs_mkfile(const char *name);
/**
 *\brief 创建link文件
 *
 *\param name     文件名
 *\return 0 成功，-1 失败
 */
int vfs_link(const char *name, const char *target_name);
/**
 *\brief 创建symlink文件
 *
 *\param name     文件名
 *\return 0 成功，-1 失败
 */
int vfs_symlink(const char *name, const char *target_name);

int vfs_mknod(const char *name, uint16_t umode, int dev);

int vfs_chmod(const char *path, uint16_t mode);
int vfs_fchmod(fd_t *fd, uint16_t mode);

int vfs_chown(const char *path, uint64_t uid, uint64_t gid);

/**
 *\brief 读取文件
 *
 *\param file     文件句柄
 *\param addr     读取的数据
 *\param offset   读取的偏移
 *\param size     读取的大小
 *\return 0 成功，-1 失败
 */
ssize_t vfs_read(vfs_node_t file, void *addr, size_t offset, size_t size);
/**
 *\brief 写入文件
 *
 *\param file     文件句柄
 *\param addr     写入的数据
 *\param offset   写入的偏移
 *\param size     写入的大小
 *\return 0 成功，-1 失败
 */
ssize_t vfs_write(vfs_node_t file, const void *addr, size_t offset,
                  size_t size);

ssize_t vfs_read_fd(fd_t *fd, void *addr, size_t offset, size_t size);
ssize_t vfs_write_fd(fd_t *fd, const void *addr, size_t offset, size_t size);

/**
 *\brief 挂载文件系统
 *
 *\param src      源文件地址
 *\param node     挂载到的节点
 *\return 0 成功，-1 失败
 */
int vfs_mount(uint64_t dev, vfs_node_t node, const char *type);
/**
 *\brief 卸载文件系统
 *
 *\param path     文件路径
 *\return 0 成功，-1 失败
 */
int vfs_unmount(const char *path);
int vfs_remount(vfs_node_t old, vfs_node_t node);

/**
 *\brief 关闭文件
 *
 *\param node     文件节点
 *\return 0 成功，-1 失败
 */
int vfs_close(vfs_node_t fd);

/**
 *\brief 删除文件
 *
 *\param node     文件节点
 *\return 0 成功，-1 失败
 */
int vfs_delete(vfs_node_t node);

/**
 *\brief 重命名文件
 *
 *\param node     文件节点
 *\param new      新路径
 *\return 0 成功，-1 失败
 */
int vfs_rename(vfs_node_t node, const char *new);

/**
 *\brief 控制文件
 *
 *\param node     文件节点
 *\param cmd      命令
 *\param arg      参数
 *\return 0 成功，-1 失败
 */
int vfs_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg);

/**
 *\brief 读取链接
 *
 *\param path   目录
 *\param node    节点
 *\return 0 成功，-1 失败
 */
int vfs_readlink(vfs_node_t node, char *buf, size_t bufsize);

/**
 *\brief 更新文件信息
 *
 *\param node     文件节点
 */
void vfs_update(vfs_node_t node);

/**
 *\brief 修改文件大小
 *
 *\param node     文件节点
 *\param size     新长度
 */
void vfs_resize(vfs_node_t node, uint64_t size);

/**
 *\brief 获取文件的完整路径
 *
 *\param node     文件节点
 */
char *vfs_get_fullpath(vfs_node_t node);

/**
 *\brief 轮询等待
 *
 *\param node     文件节点
 */
int vfs_poll(vfs_node_t node, size_t event);

fd_t *vfs_dup(fd_t *fd);

void *vfs_map(fd_t *fd, uint64_t addr, uint64_t len, uint64_t prot,
              uint64_t flags, uint64_t offset);

extern int fs_nextid;

static inline uint32_t alloc_fake_inode() {
    static uint32_t next_inode = 0x80000001;
    return next_inode++;
}

void vfs_merge_nodes_to(vfs_node_t dest, vfs_node_t source);
vfs_node_t vfs_get_real_node(vfs_node_t node);
