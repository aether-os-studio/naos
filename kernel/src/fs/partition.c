#include "fs/vfs/vfs.h"
#include "fs/vfs/dev.h"
#include "fs/partition.h"
#include "block/block.h"
#include "drivers/kernel_logger.h"
#include "arch/arch.h"

partition_t partitions[MAX_PARTITIONS_NUM] = {0};
uint64_t partition_num = 0;

ssize_t partition_read(void *data, void *buf, uint64_t offset, uint64_t len,
                       uint64_t flags) {
    partition_t *part = (partition_t *)data;
    return blkdev_read(part->blkdev_id, part->starting_lba * 512 + offset, buf,
                       len);
}

ssize_t partition_write(void *data, const void *buf, uint64_t offset,
                        uint64_t len, uint64_t flags) {
    partition_t *part = (partition_t *)data;
    return blkdev_write(part->blkdev_id, part->starting_lba * 512 + offset, buf,
                        len);
}

int partition_ioctl(void *data, int cmd, void *args) {
    partition_t *part = (partition_t *)data;
    switch (cmd) {
    case DEV_CMD_SECTOR_START:
        return part->starting_lba;
    case DEV_CMD_SECTOR_COUNT:
        return part->ending_lba - part->starting_lba + 1;
    case DEV_CMD_SECTOR_SIZE:
        return 512;
    default:
        return -EINVAL;
    }
}

#define ROOTFS_TYPE "ext"

bool have_usb_device = false;

void set_have_usb_storage(bool have) { have_usb_device = have; }

void mount_root() {
    bool err = true;

    for (uint64_t i = 0; i < partition_num; i++) {
        if (!vfs_mount(partitions[i].dev, rootdir, ROOTFS_TYPE)) {
            err = false;
            break;
        }
    }

    if (err) {
        printk("Mount root from harddisk failed\n");

    retry:
        while (!have_usb_device) {
            arch_enable_interrupt();
            arch_wait_for_interrupt();
        }
        arch_disable_interrupt();

        for (uint64_t i = 0; i < partition_num; i++) {
            if (!vfs_mount(partitions[i].dev, rootdir, ROOTFS_TYPE)) {
                err = false;
                return;
            }
        }

        printk("Mount root from usb storage failed\n");

        have_usb_device = false;

        goto retry;
    }
}
