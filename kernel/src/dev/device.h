#pragma once

#include <libs/klibc.h>

#define DEVICE_NR 256 // 设备数量
#define NAMELEN 16

// 设备类型
enum device_type_t {
    DEV_NULL,  // 空设备
    DEV_CHAR,  // 字符设备
    DEV_BLOCK, // 块设备
    DEV_NET,   // 网络设备
};

// 设备子类型
enum device_subtype_t {
    DEV_CONSOLE = 1, // 控制台
    DEV_INPUT = 13,  // 输入设备
    DEV_FB,          // 帧缓冲
    DEV_TTY,         // TTY 设备
    DEV_DISK,        // 磁盘
    DEV_PART,        // 磁盘分区
    DEV_NETIF,       // 网卡
    DEV_SYSDEV,      // 系统设备
    DEV_GPU = 226,   // 显卡
    DEV_MAX,
};

typedef struct device_t {
    char name[NAMELEN]; // 设备名
    int type;           // 设备类型
    int subtype;        // 设备子类型
    uint64_t dev;       // 设备号
    uint64_t parent;    // 父设备号
    void *ptr;          // 设备指针

    // 设备控制
    int (*ioctl)(void *dev, int cmd, void *args);
    // 轮询
    int (*poll)(void *dev, int events);
    // 读设备
    ssize_t (*read)(void *dev, void *buf, uint64_t offset, size_t size,
                    uint64_t flags);
    // 写设备
    ssize_t (*write)(void *dev, void *buf, uint64_t offset, size_t size,
                     uint64_t flags);

    void *(*map)(void *dev, void *addr, size_t offset, size_t size, size_t prot,
                 size_t flags);
} device_t;

enum device_cmd_t {
    DEV_CMD_SECTOR_START = 1, // 获得设备扇区开始位置 lba
    DEV_CMD_SECTOR_COUNT,     // 获得设备扇区数量
    DEV_CMD_SECTOR_SIZE,      // 获得设备扇区大小
};

// 安装设备
uint64_t device_install(int type, int subtype, void *ptr, char *name,
                        uint64_t parent, void *ioctl, void *poll, void *read,
                        void *write, void *map);

// 根据子类型查找设备
device_t *device_find(int type, uint64_t idx);

// 根据设备号查找设备
device_t *device_get(uint64_t dev);

// 控制设备
int device_ioctl(uint64_t dev, int cmd, void *args);

// 轮询
int device_poll(uint64_t dev, int events);

// 读设备
ssize_t device_read(uint64_t dev, void *buf, uint64_t idx, size_t count,
                    uint64_t flags);

// 写设备
ssize_t device_write(uint64_t dev, void *buf, uint64_t idx, size_t count,
                     uint64_t flags);

void *device_map(uint64_t dev, void *addr, size_t offset, size_t size,
                 size_t prot, size_t flags);

void device_init();
