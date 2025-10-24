#include <block/block.h>
#include <mm/mm.h>
#include <fs/partition.h>
#include <fs/vfs/dev.h>

blkdev_t blk_devs[MAX_BLKDEV_NUM];
uint64_t blk_devnum = 0;

void regist_blkdev(char *name, void *ptr, uint64_t block_size, uint64_t size,
                   uint64_t max_op_size,
                   uint64_t (*read)(void *data, uint64_t lba, void *buffer,
                                    uint64_t size),
                   uint64_t (*write)(void *data, uint64_t lba, void *buffer,
                                     uint64_t size)) {
    blk_devs[blk_devnum].name = strdup((const char *)name);
    blk_devs[blk_devnum].ptr = ptr;
    blk_devs[blk_devnum].block_size = block_size ? block_size : 512;
    blk_devs[blk_devnum].size = size;
    blk_devs[blk_devnum].max_op_size = max_op_size;
    blk_devs[blk_devnum].op_buffer = alloc_frames_bytes(max_op_size);
    blk_devs[blk_devnum].lock.lock = 0;
    blk_devs[blk_devnum].read = read;
    blk_devs[blk_devnum].write = write;

    char n[32];
    snprintf(n, sizeof(n), "blk%d", blk_devnum);

    uint64_t blkdev_nr =
        device_install(DEV_BLOCK, DEV_DISK, &blk_devs[blk_devnum], n, 0, NULL,
                       NULL, NULL, NULL, NULL);

    for (uint64_t i = blk_devnum; i <= blk_devnum; i++) {
        partition_t *part = &partitions[partition_num];

        struct GPT_DPT *buffer =
            (struct GPT_DPT *)malloc(sizeof(struct GPT_DPT));
        blkdev_read(i, 512, buffer, sizeof(struct GPT_DPT));

        if (memcmp(buffer->signature, GPT_HEADER_SIGNATURE, 8) ||
            buffer->num_partition_entries == 0 ||
            buffer->partition_entry_lba == 0) {
            free(buffer);
            goto probe_mbr;
        }

        struct GPT_DPTE *dptes =
            (struct GPT_DPTE *)malloc(128 * sizeof(struct GPT_DPTE));
        blkdev_read(i, buffer->partition_entry_lba * 512, dptes,
                    128 * sizeof(struct GPT_DPTE));

        for (uint32_t j = 0; j < 128; j++) {
            if (dptes[j].starting_lba == 0 || dptes[j].ending_lba == 0)
                continue;

            part->blkdev_id = i;
            part->starting_lba = dptes[j].starting_lba;
            part->ending_lba = dptes[j].ending_lba;
            part->type = GPT;

            // Register partition to devfs
            char name[32];
            sprintf(name, "part%d", i);
            partitions[partition_num].dev =
                device_install(DEV_BLOCK, DEV_PART, &partitions[partition_num],
                               name, blkdev_nr, partition_ioctl, NULL,
                               partition_read, partition_write, NULL);

            partition_num++;
        }

        free(dptes);
        free(buffer);

        continue;

    probe_mbr:
        char *iso9660_detect = (char *)malloc(5);
        memset(iso9660_detect, 0, 5);
        blkdev_read(i, 0x8001, iso9660_detect, 5);
        if (!memcmp(iso9660_detect, "CD001", 5)) {
            part->blkdev_id = i;
            part->starting_lba = 0;
            part->ending_lba = blkdev_ioctl(i, IOCTL_GETSIZE, 0) / 512;
            part->type = RAW;

            // Register partition to devfs
            char name[32];
            sprintf(name, "part%d", i);
            partitions[partition_num].dev =
                device_install(DEV_BLOCK, DEV_PART, &partitions[partition_num],
                               name, blkdev_nr, partition_ioctl, NULL,
                               partition_read, partition_write, NULL);

            partition_num++;

            free(iso9660_detect);

            continue;
        }

        struct MBR_DPT *boot_sector =
            (struct MBR_DPT *)malloc(sizeof(struct MBR_DPT));
        blkdev_read(i, 0, boot_sector, sizeof(struct MBR_DPT));

        if (boot_sector->bs_trail_sig != 0xAA55) {
            part->blkdev_id = i;
            part->starting_lba = 0;
            part->ending_lba = blkdev_ioctl(i, IOCTL_GETSIZE, 0) / 512 - 1;
            part->type = RAW;

            // Register partition to devfs
            char name[32];
            sprintf(name, "part%d", i);
            partitions[partition_num].dev =
                device_install(DEV_BLOCK, DEV_PART, &partitions[partition_num],
                               name, blkdev_nr, partition_ioctl, NULL,
                               partition_read, partition_write, NULL);

            partition_num++;
            continue;
        }

        for (int j = 0; j < MBR_MAX_PARTITION_NUM; j++) {
            if (boot_sector->dpte[j].start_lba == 0 ||
                boot_sector->dpte[j].sectors_limit == 0)
                continue;

            part->blkdev_id = i;
            part->starting_lba = boot_sector->dpte[j].start_lba;
            part->ending_lba = boot_sector->dpte[j].sectors_limit;
            part->type = MBR;

            // Register partition to devfs
            char name[32];
            sprintf(name, "part%d", i);
            partitions[partition_num].dev =
                device_install(DEV_BLOCK, DEV_PART, &partitions[partition_num],
                               name, blkdev_nr, partition_ioctl, NULL,
                               partition_read, partition_write, NULL);

            partition_num++;
        }

        // ok:
        free(boot_sector);
    }

    blk_devnum++;
}

void unregist_blkdev(void *ptr) {
    for (int i = 0; i < MAX_BLKDEV_NUM; i++) {
        if (blk_devs[i].ptr == ptr) {
            free(blk_devs[i].name);
            free_frames_bytes(blk_devs[i].op_buffer, blk_devs[i].max_op_size);
            blk_devs[i].ptr = NULL;
            blk_devs[i].block_size = 0;
            blk_devs[i].max_op_size = 0;
            blk_devs[i].size = 0;
            blk_devs[i].read = NULL;
            blk_devs[i].write = NULL;
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
    blkdev_t *dev = &blk_devs[drive];
    if (!dev || !dev->ptr || !dev->read) {
        return (uint64_t)-1;
    }

    uint64_t start_sector = offset / dev->block_size;
    uint64_t end_sector = (offset + len - 1) / dev->block_size;
    uint64_t sector_count = end_sector - start_sector + 1;
    uint64_t offset_in_block = offset % dev->block_size;

    uint8_t *tmp = dev->op_buffer;

    spin_lock(&dev->lock);

    if ((offset_in_block == 0) && ((len % dev->block_size) == 0)) {
        uint64_t total_copied = 0;
        uint64_t remaining_sectors = sector_count;
        while (remaining_sectors > 0) {
            uint64_t to_copy_sectors =
                MIN(remaining_sectors, dev->max_op_size / dev->block_size);
            uint64_t ret = dev->read(
                dev->ptr, start_sector + total_copied / dev->block_size, tmp,
                to_copy_sectors);
            uint64_t to_copy_bytes = to_copy_sectors * dev->block_size;
            memcpy(buf + total_copied, dev->op_buffer, to_copy_bytes);
            total_copied += to_copy_bytes;
            remaining_sectors -= to_copy_sectors;
        }
        spin_unlock(&dev->lock);
        return total_copied;
    }

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
            printk("Read block device failed!!!\n");
            spin_unlock(&dev->lock);
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

    spin_unlock(&dev->lock);

    return total_read;
}

uint64_t blkdev_write(uint64_t drive, uint64_t offset, const void *buf,
                      uint64_t len) {
    blkdev_t *dev = &blk_devs[drive];
    if (!dev || !dev->ptr || !dev->write) {
        return (uint64_t)-1;
    }

    uint64_t start_sector = offset / dev->block_size;
    uint64_t end_sector = (offset + len - 1) / dev->block_size;
    uint64_t sector_count = end_sector - start_sector + 1;
    uint64_t offset_in_block = offset % dev->block_size;

    uint8_t *tmp = dev->op_buffer;

    spin_lock(&dev->lock);

    if ((offset_in_block == 0) && ((len % dev->block_size) == 0)) {
        uint64_t total_copied = 0;
        uint64_t remaining_sectors = sector_count;
        while (remaining_sectors > 0) {
            uint64_t to_copy_sectors =
                MIN(remaining_sectors, dev->max_op_size / dev->block_size);
            uint64_t to_copy_bytes = to_copy_sectors * dev->block_size;
            memcpy(dev->op_buffer, buf + total_copied, to_copy_bytes);
            uint64_t ret = dev->write(
                dev->ptr, start_sector + total_copied / dev->block_size, tmp,
                to_copy_sectors);
            total_copied += to_copy_bytes;
            remaining_sectors -= to_copy_sectors;
        }
        spin_unlock(&dev->lock);
        return total_copied;
    }

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
                printk("Read block device failed!!!\n");
                spin_unlock(&dev->lock);
                return (uint64_t)-1;
            }
        }

        // 复制数据到临时缓冲区
        uint64_t copy_size = (chunk_size > remaining) ? remaining : chunk_size;

        memcpy(tmp + offset_in_block, src, copy_size);

        // 执行块设备写入
        if (dev->write(dev->ptr, start_sector, tmp, chunk_sectors) !=
            chunk_sectors) {
            printk("Write block device failed!!!\n");
            spin_unlock(&dev->lock);
            return (uint64_t)-1;
        }

        // 更新状态
        src += copy_size;
        remaining -= copy_size;
        total_written += copy_size;
        start_sector += chunk_sectors;
        offset_in_block = 0; // 第一次之后不需要再处理块内偏移
    }

    spin_unlock(&dev->lock);

    return total_written;
}
