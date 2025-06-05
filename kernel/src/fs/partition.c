#include "fs/vfs/vfs.h"
#include "fs/vfs/dev.h"
#include "fs/partition.h"
#include "block/block.h"
#include "drivers/kernel_logger.h"
#include "arch/arch.h"

partition_t partitions[MAX_PARTITIONS_NUM];
struct GPT_DPTE dpte[MAX_PARTITIONS_NUM];
uint64_t partition_num;

ssize_t partition_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    partition_t *part = (partition_t *)data;
    return blkdev_read(part->blkdev_id, part->starting_lba * 512 + offset, buf, len);
}

ssize_t partition_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    partition_t *part = (partition_t *)data;
    return blkdev_write(part->blkdev_id, part->starting_lba * 512 + offset, buf, len);
}

void partition_init()
{
    partition_num = 0;
    memset(partitions, 0, sizeof(partitions));

    for (uint64_t i = 0; i < blk_devnum; i++)
    {
        partition_t *part = &partitions[partition_num];

        struct GPT_DPT *buffer = (struct GPT_DPT *)malloc(sizeof(struct GPT_DPT));
        blkdev_read(i, 512, buffer, sizeof(struct GPT_DPT));

        if (memcmp(buffer->signature, GPT_HEADER_SIGNATURE, 8) || buffer->num_partition_entries == 0 || buffer->partition_entry_lba == 0)
        {
            free(buffer);
            goto probe_mbr;
        }

        uint64_t num_partitions = buffer->num_partition_entries / buffer->size_of_partition_entry;

        struct GPT_DPTE *dptes = (struct GPT_DPTE *)malloc(buffer->num_partition_entries);
        blkdev_read(i, buffer->partition_entry_lba * 512, dptes, buffer->num_partition_entries);

        for (uint32_t j = 0; j < num_partitions; j++)
        {
            part->blkdev_id = i;
            part->starting_lba = dptes[j].starting_lba;
            part->ending_lba = dptes[j].ending_lba;
            part->type = GPT;
            partition_num++;
        }

        free(dptes);
        free(buffer);

        continue;

    probe_mbr:
        char *iso9660_detect = (char *)malloc(5);
        memset(iso9660_detect, 0, 5);
        blkdev_read(i, 0x8001, iso9660_detect, 5);
        if (!memcmp(iso9660_detect, "CD001", 5))
        {
            part->blkdev_id = i;
            part->starting_lba = 0;
            part->ending_lba = 0;
            part->type = RAW;
            partition_num++;

            free(iso9660_detect);

            continue;
        }

        struct MBR_DPT *boot_sector = (struct MBR_DPT *)malloc(sizeof(struct MBR_DPT));
        blkdev_read(i, 0, boot_sector, sizeof(struct MBR_DPT));

        if (boot_sector->bs_trail_sig != 0xAA55)
        {
            part->blkdev_id = i;
            part->starting_lba = 0;
            part->ending_lba = 0;
            part->type = RAW;
            partition_num++;
            continue;
        }

        for (int j = 0; j < MBR_MAX_PARTITION_NUM; j++)
        {
            if (boot_sector->dpte[j].start_lba == 0 || boot_sector->dpte[j].sectors_limit == 0)
                continue;

            part->blkdev_id = i;
            part->starting_lba = boot_sector->dpte[j].start_lba;
            part->ending_lba = boot_sector->dpte[j].sectors_limit;
            part->type = MBR;
            partition_num++;
        }

        // ok:
        free(boot_sector);
    }

    for (uint64_t i = 0; i < partition_num; i++)
    {
        char name[MAX_DEV_NAME_LEN];
        sprintf(name, "part%d", i);
        regist_dev(name, partition_read, partition_write, NULL, NULL, NULL, &partitions[i]);
    }
}

void mount_root()
{
    bool err = true;

    for (uint64_t i = 0; i < partition_num; i++)
    {
        char buf[11];
        sprintf(buf, "/dev/part%d", i);

        if (!vfs_mount((const char *)buf, rootdir))
        {
            err = false;
            break;
        }
    }

    if (err)
    {
        printk("Mount root failed\n");
        while (1)
        {
            arch_pause();
        }
    }
}
