#include <block/block.h>
#include <mm/mm.h>

blkdev_t blk_devs[MAX_BLKDEV_NUM];
uint64_t blk_devnum = 0;

void regist_blkdev(char *name, void *ptr, uint64_t block_size, uint64_t size, uint64_t (*read)(void *data, uint64_t lba, void *buffer, uint64_t size), uint64_t (*write)(void *data, uint64_t lba, void *buffer, uint64_t size))
{
    blk_devs[blk_devnum].name = name;
    blk_devs[blk_devnum].ptr = ptr;
    blk_devs[blk_devnum].block_size = block_size;
    blk_devs[blk_devnum].size = size;
    blk_devs[blk_devnum].read = read;
    blk_devs[blk_devnum].write = write;
    blk_devnum++;
}

uint64_t blkdev_ioctl(uint64_t drive, uint64_t cmd, uint64_t arg)
{
    switch (cmd)
    {
    case IOCTL_GETSIZE:
        return blk_devs[drive].size;
    case IOCTL_GETBLKSIZE:
        return blk_devs[drive].block_size;

    default:
        break;
    }

    return 0;
}

uint64_t blkdev_read(uint64_t drive, uint64_t offset, void *buf, uint64_t len)
{
    blkdev_t *dev = &blk_devs[drive];
    if (!dev)
        return (uint64_t)-1;

    uint64_t start = offset;
    uint64_t end = offset + len;

    uint64_t start_sector_read_start = offset % dev->block_size;

    uint64_t start_sector_id = start / dev->block_size;
    uint64_t end_sector_id = (end - 1) / dev->block_size;

    uint64_t buffer_size = (end_sector_id - start_sector_id + 1) * dev->block_size;

    uint8_t *tmp = phys_to_virt((uint8_t *)alloc_frames((buffer_size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE));
    memset(tmp, 0, buffer_size);

    dev->read(dev->ptr, start_sector_id, tmp, buffer_size / dev->block_size);

    memcpy(buf, tmp + start_sector_read_start, len);

    free_frames(virt_to_phys((uint64_t)tmp), (buffer_size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);

    return len;
}

uint64_t blkdev_write(uint64_t drive, uint64_t offset, void *buf, uint64_t len)
{
    blkdev_t *dev = &blk_devs[drive];
    if (!dev)
        return (uint64_t)-1;

    uint64_t start = offset;
    uint64_t end = offset + len;

    uint64_t start_sector_read_start = offset % dev->block_size;

    uint64_t start_sector_id = start / dev->block_size;
    uint64_t end_sector_id = (end - 1) / dev->block_size;

    uint64_t buffer_size = (end_sector_id - start_sector_id + 1) * dev->block_size;

    uint8_t *tmp = phys_to_virt((uint8_t *)alloc_frames((buffer_size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE));
    memset(tmp, 0, buffer_size);

    dev->read(dev->ptr, start_sector_id, tmp, buffer_size / dev->block_size);

    memcpy(tmp + start_sector_read_start, buf, len);

    dev->write(dev->ptr, start_sector_id, tmp, buffer_size / dev->block_size);

    free_frames(virt_to_phys((uint64_t)tmp), (buffer_size + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE);

    return len;
}
