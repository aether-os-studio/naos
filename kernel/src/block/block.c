#include <block/block.h>
#include <mm/mm.h>
#include <fs/partition.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/sys.h>
#include <arch/arch.h>
#include <task/task.h>

blkdev_t blk_devs[MAX_BLKDEV_NUM];
uint64_t blk_devnum = 0;

uint64_t device_regist_blk(int subtype, void *data, char *name, void *ioctl,
                           void *read, void *write) {
    return device_install(DEV_BLOCK, subtype, data, name, 0, NULL, NULL, ioctl,
                          NULL, read, write, NULL);
}

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
    blk_devs[blk_devnum].read = read;
    blk_devs[blk_devnum].write = write;

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
            sprintf(name, "part%d", j);
            partitions[partition_num].dev = device_regist_blk(
                DEV_PART, &partitions[partition_num], name, partition_ioctl,
                partition_read, partition_write);
            char uevent[256];
            sprintf(
                uevent,
                "SUBSYSTEM=block\nDEVTYPE=partition\nDEVNAME=%s\nDISKSEQ=%d\n",
                name, partition_num + 1);
            sysfs_regist_dev('b', (partitions[partition_num].dev >> 8) & 0xFF,
                             partitions[partition_num].dev & 0xFF, "", name,
                             uevent);

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
            partitions[partition_num].dev = device_regist_blk(
                DEV_PART, &partitions[partition_num], name, partition_ioctl,
                partition_read, partition_write);
            char uevent[256];
            sprintf(
                uevent,
                "SUBSYSTEM=block\nDEVTYPE=partition\nDEVNAME=%s\nDISKSEQ=%d\n",
                name, partition_num + 1);
            sysfs_regist_dev('b', (partitions[partition_num].dev >> 8) & 0xFF,
                             partitions[partition_num].dev & 0xFF, "", name,
                             uevent);

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
            partitions[partition_num].dev = device_regist_blk(
                DEV_PART, &partitions[partition_num], name, partition_ioctl,
                partition_read, partition_write);
            char uevent[256];
            sprintf(
                uevent,
                "SUBSYSTEM=block\nDEVTYPE=partition\nDEVNAME=%s\nDISKSEQ=%d\n",
                name, partition_num + 1);
            sysfs_regist_dev('b', (partitions[partition_num].dev >> 8) & 0xFF,
                             partitions[partition_num].dev & 0xFF, "", name,
                             uevent);

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
            partitions[partition_num].dev = device_regist_blk(
                DEV_PART, &partitions[partition_num], name, partition_ioctl,
                partition_read, partition_write);
            char uevent[256];
            sprintf(
                uevent,
                "SUBSYSTEM=block\nDEVTYPE=partition\nDEVNAME=%s\nDISKSEQ=%d\n",
                name, partition_num + 1);
            sysfs_regist_dev('b', (partitions[partition_num].dev >> 8) & 0xFF,
                             partitions[partition_num].dev & 0xFF, "", name,
                             uevent);

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

#define DMA_ALIGN DEFAULT_PAGE_SIZE
#define IS_DMA_BUF(p) (((uintptr_t)(p) & (DMA_ALIGN - 1)) == 0)

uint64_t blkdev_read(uint64_t drive, uint64_t offset, void *buf, uint64_t len) {
    blkdev_t *dev = &blk_devs[drive];
    if (!dev || !dev->ptr || !dev->read)
        return (uint64_t)-1;
    if (len == 0)
        return 0;

    const uint64_t bs = dev->block_size;
    const uint64_t max_sec = dev->max_op_size / bs;
    uint8_t *dst = (uint8_t *)buf;
    uint64_t sector = offset / bs;
    uint64_t blk_off = offset % bs;
    uint64_t rem = len;
    uint64_t total = 0;

    if (blk_off == 0 && (len % bs) == 0 && IS_DMA_BUF(dst)) {
        uint64_t secs_left = len / bs;
        while (secs_left > 0) {
            uint64_t n = MIN(secs_left, max_sec);
            if (dev->read(dev->ptr, sector, dst, n) != n)
                return (uint64_t)-1;
            uint64_t bytes = n * bs;
            dst += bytes;
            sector += n;
            secs_left -= n;
            total += bytes;
        }
        return total;
    }

    if (blk_off != 0) {
        uint64_t head = MIN(bs - blk_off, rem);
        uint8_t *bounce = alloc_frames_bytes(bs);

        if (dev->read(dev->ptr, sector, bounce, 1) != 1) {
            free_frames_bytes(bounce, bs);
            return (uint64_t)-1;
        }
        memcpy(dst, bounce + blk_off, head);
        free_frames_bytes(bounce, bs);

        dst += head;
        rem -= head;
        total += head;
        sector++;
    }

    uint64_t mid_secs = rem / bs;

    if (mid_secs > 0 && IS_DMA_BUF(dst)) {
        while (mid_secs > 0) {
            uint64_t n = MIN(mid_secs, max_sec);
            if (dev->read(dev->ptr, sector, dst, n) != n)
                return (uint64_t)-1;
            uint64_t bytes = n * bs;
            dst += bytes;
            rem -= bytes;
            total += bytes;
            sector += n;
            mid_secs -= n;
        }
    } else if (mid_secs > 0) {
        uint64_t bn = MIN(mid_secs, max_sec);
        uint64_t bsz = bn * bs;
        uint8_t *bounce = alloc_frames_bytes(bsz);

        while (mid_secs > 0) {
            uint64_t n = MIN(mid_secs, bn);
            if (dev->read(dev->ptr, sector, bounce, n) != n) {
                free_frames_bytes(bounce, bsz);
                return (uint64_t)-1;
            }
            uint64_t bytes = n * bs;
            memcpy(dst, bounce, bytes);
            dst += bytes;
            rem -= bytes;
            total += bytes;
            sector += n;
            mid_secs -= n;
        }
        free_frames_bytes(bounce, bsz);
    }

    if (rem > 0) {
        uint8_t *bounce = alloc_frames_bytes(bs);

        if (dev->read(dev->ptr, sector, bounce, 1) != 1) {
            free_frames_bytes(bounce, bs);
            return (uint64_t)-1;
        }
        memcpy(dst, bounce, rem);
        free_frames_bytes(bounce, bs);
        total += rem;
    }

    return total;
}

uint64_t blkdev_write(uint64_t drive, uint64_t offset, const void *buf,
                      uint64_t len) {
    blkdev_t *dev = &blk_devs[drive];
    if (!dev || !dev->ptr || !dev->write)
        return (uint64_t)-1;
    if (len == 0)
        return 0;

    const uint64_t bs = dev->block_size;
    const uint64_t max_sec = dev->max_op_size / bs;
    const uint8_t *src = (const uint8_t *)buf;
    uint64_t sector = offset / bs;
    uint64_t blk_off = offset % bs;
    uint64_t rem = len;
    uint64_t total = 0;

    if (blk_off == 0 && (len % bs) == 0 && IS_DMA_BUF(src)) {
        uint64_t secs_left = len / bs;
        while (secs_left > 0) {
            uint64_t n = MIN(secs_left, max_sec);
            if (dev->write(dev->ptr, sector, (void *)src, n) != n)
                return (uint64_t)-1;
            uint64_t bytes = n * bs;
            src += bytes;
            sector += n;
            secs_left -= n;
            total += bytes;
        }
        return total;
    }

    if (blk_off != 0) {
        if (!dev->read)
            return (uint64_t)-1;

        uint64_t head = MIN(bs - blk_off, rem);
        uint8_t *bounce = alloc_frames_bytes(bs);

        if (dev->read(dev->ptr, sector, bounce, 1) != 1) {
            free_frames_bytes(bounce, bs);
            return (uint64_t)-1;
        }
        memcpy(bounce + blk_off, src, head);
        if (dev->write(dev->ptr, sector, bounce, 1) != 1) {
            free_frames_bytes(bounce, bs);
            return (uint64_t)-1;
        }
        free_frames_bytes(bounce, bs);

        src += head;
        rem -= head;
        total += head;
        sector++;
    }

    uint64_t mid_secs = rem / bs;

    if (mid_secs > 0 && IS_DMA_BUF(src)) {
        while (mid_secs > 0) {
            uint64_t n = MIN(mid_secs, max_sec);
            if (dev->write(dev->ptr, sector, (void *)src, n) != n)
                return (uint64_t)-1;
            uint64_t bytes = n * bs;
            src += bytes;
            rem -= bytes;
            total += bytes;
            sector += n;
            mid_secs -= n;
        }
    } else if (mid_secs > 0) {
        uint64_t bn = MIN(mid_secs, max_sec);
        uint64_t bsz = bn * bs;
        uint8_t *bounce = alloc_frames_bytes(bsz);

        while (mid_secs > 0) {
            uint64_t n = MIN(mid_secs, bn);
            uint64_t bytes = n * bs;
            memcpy(bounce, src, bytes);
            if (dev->write(dev->ptr, sector, bounce, n) != n) {
                free_frames_bytes(bounce, bsz);
                return (uint64_t)-1;
            }
            src += bytes;
            rem -= bytes;
            total += bytes;
            sector += n;
            mid_secs -= n;
        }
        free_frames_bytes(bounce, bsz);
    }

    if (rem > 0) {
        if (!dev->read)
            return (uint64_t)-1;

        uint8_t *bounce = alloc_frames_bytes(bs);
        if (dev->read(dev->ptr, sector, bounce, 1) != 1) {
            free_frames_bytes(bounce, bs);
            return (uint64_t)-1;
        }
        memcpy(bounce, src, rem);
        if (dev->write(dev->ptr, sector, bounce, 1) != 1) {
            free_frames_bytes(bounce, bs);
            return (uint64_t)-1;
        }
        free_frames_bytes(bounce, bs);
        total += rem;
    }

    return total;
}
