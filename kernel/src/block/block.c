#include <block/block.h>
#include <mm/mm.h>

blkdev_t blk_devs[MAX_BLKDEV_NUM];
uint64_t blk_devnum = 0;

spinlock_t blockdev_op_lock = {0};

void regist_blkdev(char *name, void *ptr, uint64_t block_size, uint64_t size,
                   uint64_t max_op_size,
                   uint64_t (*read)(void *data, uint64_t lba, void *buffer,
                                    uint64_t size),
                   uint64_t (*write)(void *data, uint64_t lba, void *buffer,
                                     uint64_t size)) {
    blk_devs[blk_devnum].name = strdup((const char *)name);
    blk_devs[blk_devnum].ptr = ptr;
    blk_devs[blk_devnum].block_size = block_size ? block_size : 512;
    blk_devs[blk_devnum].max_op_size = max_op_size;
    blk_devs[blk_devnum].size = size;
    blk_devs[blk_devnum].read = read;
    blk_devs[blk_devnum].write = write;
    blk_devnum++;
}

void unregist_blkdev(void *ptr) {
    for (int i = 0; i < MAX_BLKDEV_NUM; i++) {
        if (blk_devs[i].ptr == ptr) {
            free(blk_devs[i].name);
            blk_devs[i].ptr = NULL;
            blk_devs[i].block_size = 0;
            blk_devs[i].max_op_size = 0;
            blk_devs[i].size = 0;
            blk_devs[i].read = NULL;
            blk_devs[i].write = NULL;
            memmove(&blk_devs[i], &blk_devs[i + 1],
                    (blk_devnum - i - 1) * sizeof(blkdev_t));
            blk_devnum--;
        }
    }
}

uint64_t blkdev_ioctl(uint64_t drive, uint64_t cmd, uint64_t arg) {
    switch (cmd) {
    case IOCTL_GETSIZE:
        return blk_devs[drive].size;
    case IOCTL_GETBLKSIZE:
        return blk_devs[drive].block_size;

    default:
        break;
    }

    return 0;
}

uint64_t blkdev_read(uint64_t drive, uint64_t offset, void *buf, uint64_t len) {
    spin_lock(&blockdev_op_lock);

    blkdev_t *dev = &blk_devs[drive];
    if (!dev || !dev->ptr || !dev->read) {
        spin_unlock(&blockdev_op_lock);
        return (uint64_t)-1;
    }

    uint64_t start_sector = offset / dev->block_size;
    uint64_t end_sector = (offset + len - 1) / dev->block_size;
    uint64_t sector_count = end_sector - start_sector + 1;
    uint64_t offset_in_block = offset % dev->block_size;

    uint8_t *tmp = alloc_frames_bytes(sector_count * dev->block_size);
    uint64_t total_read = 0;
    uint64_t remaining = len;
    uint8_t *dest = (uint8_t *)buf;

    while (remaining > 0) {
        // 计算本次操作的扇区数和长度
        uint64_t chunk_sectors = sector_count;
        uint64_t chunk_size = remaining;

        // 限制单次I/O大小
        if (chunk_sectors * dev->block_size > dev->max_op_size) {
            chunk_sectors = dev->max_op_size / dev->block_size;
            chunk_size = chunk_sectors * dev->block_size - offset_in_block;
            if (chunk_size > remaining) {
                chunk_size = remaining;
            }
        }

        // 执行块设备读取
        if (dev->read(dev->ptr, start_sector, tmp, chunk_sectors) !=
            chunk_sectors) {
            free_frames_bytes(tmp, sector_count * dev->block_size);
            spin_unlock(&blockdev_op_lock);
            return (uint64_t)-1;
        }

        // 复制数据到目标缓冲区
        uint64_t copy_size = (chunk_size > remaining) ? remaining : chunk_size;

        memcpy(dest, tmp + offset_in_block, copy_size);

        // 更新状态
        dest += copy_size;
        remaining -= copy_size;
        total_read += copy_size;
        start_sector += chunk_sectors;
        offset_in_block = 0; // 第一次之后不需要再处理块内偏移
    }

    free_frames_bytes(tmp, sector_count * dev->block_size);

    spin_unlock(&blockdev_op_lock);

    return total_read;
}

uint64_t blkdev_write(uint64_t drive, uint64_t offset, const void *buf,
                      uint64_t len) {
    spin_lock(&blockdev_op_lock);

    blkdev_t *dev = &blk_devs[drive];
    if (!dev || !dev->ptr || !dev->write) {
        spin_unlock(&blockdev_op_lock);
        return (uint64_t)-1;
    }

    uint64_t start_sector = offset / dev->block_size;
    uint64_t end_sector = (offset + len - 1) / dev->block_size;
    uint64_t sector_count = end_sector - start_sector + 1;
    uint64_t offset_in_block = offset % dev->block_size;

    uint8_t *tmp = alloc_frames_bytes(sector_count * dev->block_size);
    uint64_t total_written = 0;
    uint64_t remaining = len;
    const uint8_t *src = (const uint8_t *)buf;

    while (remaining > 0) {
        // 计算本次操作的扇区数和长度
        uint64_t chunk_sectors = sector_count;
        uint64_t chunk_size = remaining;

        // 限制单次I/O大小
        if (chunk_sectors * dev->block_size > dev->max_op_size) {
            chunk_sectors = dev->max_op_size / dev->block_size;
            chunk_size = chunk_sectors * dev->block_size - offset_in_block;
            if (chunk_size > remaining) {
                chunk_size = remaining;
            }
        }

        // 对于部分块写入，需要先读取原始数据
        if (offset_in_block != 0 ||
            chunk_size < chunk_sectors * dev->block_size) {
            if (dev->read(dev->ptr, start_sector, tmp, chunk_sectors) !=
                chunk_sectors) {
                free_frames_bytes(tmp, sector_count * dev->block_size);
                spin_unlock(&blockdev_op_lock);
                return (uint64_t)-1;
            }
        }

        // 复制数据到临时缓冲区
        uint64_t copy_size = (chunk_size > remaining) ? remaining : chunk_size;

        memcpy(tmp + offset_in_block, src, copy_size);

        // 执行块设备写入
        if (dev->write(dev->ptr, start_sector, tmp, chunk_sectors) !=
            chunk_sectors) {
            free_frames_bytes(tmp, sector_count * dev->block_size);
            spin_unlock(&blockdev_op_lock);
            return (uint64_t)-1;
        }

        // 更新状态
        src += copy_size;
        remaining -= copy_size;
        total_written += copy_size;
        start_sector += chunk_sectors;
        offset_in_block = 0; // 第一次之后不需要再处理块内偏移
    }

    free_frames_bytes(tmp, sector_count * dev->block_size);

    spin_unlock(&blockdev_op_lock);

    return total_written;
}
