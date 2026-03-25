#pragma once

#include <libs/klibc.h>
#include <libs/llist.h>

#define MAX_BLKDEV_NUM 64

typedef struct blkdev {
    struct llist_header list;
    char *name;
    void *ptr;
    uint64_t block_size;
    uint64_t size;
    uint64_t max_op_size;
    uint64_t id;
    bool mounted;
    uint64_t (*read)(void *data, uint64_t lba, void *buffer, uint64_t size);
    uint64_t (*write)(void *data, uint64_t lba, void *buffer, uint64_t size);
} blkdev_t;

extern struct llist_header blk_dev_list;
extern uint64_t blk_devnum;

blkdev_t *find_blkdev_by_ptr(void *ptr);
blkdev_t *find_blkdev_by_id(uint64_t id);
blkdev_t *find_blkdev_by_name(const char *name);

void blkdev_register(blkdev_t *dev);
void blkdev_unregister(blkdev_t *dev);
int blkdev_mount(blkdev_t *dev);
int blkdev_unmount(blkdev_t *dev);

void regist_blkdev(char *name, void *ptr, uint64_t block_size, uint64_t size,
                   uint64_t max_op_size,
                   uint64_t (*read)(void *data, uint64_t lba, void *buffer,
                                    uint64_t size),
                   uint64_t (*write)(void *data, uint64_t lba, void *buffer,
                                     uint64_t size));
void unregist_blkdev(void *ptr);

enum {
    IOCTL_GETBLKSIZE,
    IOCTL_GETSIZE,
};

uint64_t blkdev_ioctl(uint64_t drive, uint64_t cmd, uint64_t arg);

uint64_t blkdev_read(uint64_t drive, uint64_t offset, void *buf, uint64_t len);
uint64_t blkdev_write(uint64_t drive, uint64_t offset, const void *buf,
                      uint64_t len);
