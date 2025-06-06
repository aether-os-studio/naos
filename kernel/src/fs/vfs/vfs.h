#pragma once

#include <libs/klibc.h>
#include <fs/vfs/fcntl.h>

static inline char toupper(char ch)
{
    if (ch >= 'a' && ch <= 'z')
        ch -= 0x20;
    return ch;
}

static inline char tolower(char ch)
{
    if (ch >= 'A' && ch <= 'Z')
        ch += 0x20;
    return ch;
}

#define ALL_IMPLEMENTATION
#include "list.h"

static inline bool streq(const char *str1, const char *str2)
{
    int ret = 0;
    while (!(ret = tolower(*(unsigned char *)str1) - tolower(*(unsigned char *)str2)) && *str1)
    {
        str1++;
        str2++;
    }
    if (ret < 0)
    {
        return false;
    }
    else if (ret > 0)
    {
        return false;
    }
    return true;
}

static inline bool streqn(const char *str1, const char *str2, size_t max_size)
{
    if (max_size == 0)
    {
        return true;
    }

    while (max_size-- > 0)
    {
        int c1 = tolower((unsigned char)*str1);
        int c2 = tolower((unsigned char)*str2);

        if (c1 != c2)
        {
            return false;
        }

        if (*str1 == '\0')
        {
            return true;
        }

        str1++;
        str2++;
    }

    return true;
}

// 从字符串中提取路径
static inline char *pathtok(char **sp)
{
    char *s = *sp, *e = *sp;
    if (*s == '\0')
        return NULL;
    for (; *e != '\0' && *e != '/'; e++)
    {
    }
    *sp = e + (*e != '\0' ? 1 : 0);
    *e = '\0';
    return s;
}

#define max(x, y) ((x > y) ? (x) : (y))

typedef int64_t ssize_t;

// * 所有时间请使用 GMT 时间 *

// 读写时请 padding 到 PAGE_SIZE 的整数倍
#define FILE_BLKSIZE PAGE_SIZE

enum
{
    file_none = 0x0001UL,     // 普通文件
    file_dir = 0x0002UL,      // 文件夹
    file_symlink = 0x0004UL,  // 符号链接
    file_block = 0x0008UL,    // 块设备，如硬盘
    file_stream = 0x0010UL,   // 流式设备，如终端
    file_fbdev = 0x0020UL,    // 帧缓冲设备
    file_keyboard = 0x0040UL, // 键盘设备
    file_mouse = 0x0080UL,    // 鼠标设备
    file_pipe = 0x0100UL,     // 管道设备
    file_socket = 0x0200UL,   // 套接字设备
    file_epoll = 0x0400UL,    // epoll 设备
};

typedef struct vfs_node *vfs_node_t;

typedef int (*vfs_mount_t)(const char *src, vfs_node_t node);
typedef void (*vfs_unmount_t)(void *root);

/**
 *\brief 打开一个文件
 *
 *\param parent   父目录句柄
 *\param name     文件名
 *\param node     文件节点
 */
typedef void (*vfs_open_t)(void *parent, const char *name, vfs_node_t node);

/**
 *\brief 关闭一个文件
 *
 *\param current  当前文件句柄
 */
typedef bool (*vfs_close_t)(void *current);

/**
 *\brief 重设文件大小
 *
 *\param current  当前文件句柄
 *\param size     新的大小
 */
typedef void (*vfs_resize_t)(void *current, uint64_t size);

/**
 *\brief 写入一个文件
 *
 *\param file     文件句柄
 *\param addr     写入的数据
 *\param offset   写入的偏移
 *\param size     写入的大小
 */
typedef ssize_t (*vfs_write_t)(void *file, const void *addr, size_t offset, size_t size);

/**
 *\brief 读取一个文件
 *
 *\param file     文件句柄
 *\param addr     读取的数据
 *\param offset   读取的偏移
 *\param size     读取的大小
 */
typedef ssize_t (*vfs_read_t)(void *file, void *addr, size_t offset, size_t size);

/**
 *\brief 获取文件信息
 *
 *\param file     文件句柄
 *\param node     文件节点
 */
typedef int (*vfs_stat_t)(void *file, vfs_node_t node);

// 创建一个文件或文件夹
typedef int (*vfs_mk_t)(void *parent, const char *name, vfs_node_t node);

typedef int (*vfs_del_t)(void *parent, vfs_node_t node);

typedef int (*vfs_rename_t)(void *current, const char *new);

// 创建一个文件或文件夹
typedef int (*vfs_ioctl_t)(void *file, ssize_t cmd, ssize_t arg);

// 映射文件从 offset 开始的 size 大小
typedef void *(*vfs_mapfile_t)(void *file, void *addr, size_t offset, size_t size, size_t prot, size_t flags);

typedef int (*vfs_poll_t)(void *file, size_t events);

typedef struct vfs_callback
{
    vfs_mount_t mount;
    vfs_unmount_t unmount;
    vfs_open_t open;
    vfs_close_t close;
    vfs_read_t read;
    vfs_write_t write;
    vfs_mk_t mkdir;
    vfs_mk_t mkfile;
    vfs_del_t delete;
    vfs_rename_t rename;
    vfs_stat_t stat;
    vfs_mapfile_t map;
    vfs_ioctl_t ioctl;
    vfs_poll_t poll;
} *vfs_callback_t;

typedef struct flock
{
    volatile uint64_t l_pid;
    volatile uint64_t l_type;
    volatile uint64_t lock;
} flock_t;

struct vfs_node
{
    vfs_node_t parent;   // 父目录
    char *name;          // 名称
    char *linkname;      // 符号链接名称
    uint64_t inode;      // 节点号
    uint64_t realsize;   // 项目真实占用的空间 (可选)
    uint64_t size;       // 文件大小或若是文件夹则填0
    uint64_t blksz;      // 块大小
    uint64_t createtime; // 创建时间
    uint64_t readtime;   // 最后读取时间
    uint64_t writetime;  // 最后写入时间
    uint32_t owner;      // 所有者
    uint32_t group;      // 所有组
    uint32_t type;       // 类型
    uint32_t fsid;       // 文件系统的 id
    void *handle;        // 操作文件的句柄
    flock_t lock;        // 锁
    list_t child;        // 子目录和子文件
    vfs_node_t root;     // 根目录
    uint32_t refcount;   // 引用计数
    uint16_t mode;       // 模式
};

typedef struct fd
{
    vfs_node_t node;
    uint64_t offset;
    uint64_t flags;
} fd_t;

extern vfs_node_t rootdir; // vfs 根目录

vfs_node_t vfs_node_alloc(vfs_node_t parent, const char *name);
void vfs_free(vfs_node_t vfs);
void vfs_free_child(vfs_node_t vfs);
// 一定要记得手动设置一下child的type
vfs_node_t vfs_child_append(vfs_node_t parent, const char *name, void *handle);

bool vfs_init();

/**
 *\brief 注册一个文件系统
 *
 *\param name      文件系统名称
 *\param callback  文件系统回调
 *\return 文件系统 id
 */
int vfs_regist(const char *name, vfs_callback_t callback);

#define PATH_MAX 4096    // 路径最大长度
#define FILENAME_MAX 256 // 文件名最大长度

vfs_node_t vfs_open_at(vfs_node_t start, const char *_path, bool nosymlink);

vfs_node_t vfs_open(const char *_path);

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
ssize_t vfs_write(vfs_node_t file, const void *addr, size_t offset, size_t size);

/**
 *\brief 挂载文件系统
 *
 *\param src      源文件地址
 *\param node     挂载到的节点
 *\return 0 成功，-1 失败
 */
int vfs_mount(const char *src, vfs_node_t node, const char *type);
/**
 *\brief 卸载文件系统
 *
 *\param path     文件路径
 *\return 0 成功，-1 失败
 */
int vfs_unmount(const char *path);

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

void *vfs_map(vfs_node_t node, uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, uint64_t offset);

extern vfs_callback_t fs_callbacks[256];
