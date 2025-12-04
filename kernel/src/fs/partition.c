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
