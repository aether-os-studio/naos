#include "fs/vfs/vfs.h"
#include "fs/vfs/dev.h"
#include "fs/partition.h"
#include "block/block.h"
#include "drivers/kernel_logger.h"
#include "arch/arch.h"

partition_t partitions[MAX_PARTITIONS_NUM] = {0};
uint64_t partition_num = 0;

ssize_t partition_read(void *data, uint64_t offset, void *buf, uint64_t len,
                       uint64_t flags) {
    partition_t *part = (partition_t *)data;
    return blkdev_read(part->blkdev_id, part->starting_lba * 512 + offset, buf,
                       len);
}

ssize_t partition_write(void *data, uint64_t offset, const void *buf,
                        uint64_t len, uint64_t flags) {
    partition_t *part = (partition_t *)data;
    return blkdev_write(part->blkdev_id, part->starting_lba * 512 + offset, buf,
                        len);
}

#define ROOTFS_TYPE "ext"

bool have_usb_device = false;

void set_have_usb_storage(bool have) { have_usb_device = have; }

void mount_root() {
    bool err = true;

    for (uint64_t i = 0; i < partition_num; i++) {
        char buf[16];
        sprintf(buf, "/dev/part%d", i);

        if (!vfs_mount(partitions[i].node, rootdir, ROOTFS_TYPE)) {
            err = false;
            break;
        }
    }

    if (err) {
        while (!have_usb_device) {
            arch_pause();
        }

        for (uint64_t i = 0; i < partition_num; i++) {
            char buf[16];
            sprintf(buf, "/dev/part%d", i);

            if (!vfs_mount(partitions[i].node, rootdir, ROOTFS_TYPE)) {
                err = false;
                return;
            }
        }

        printk("Mount root failed\n");
        while (1) {
            arch_pause();
        }
    }
}
