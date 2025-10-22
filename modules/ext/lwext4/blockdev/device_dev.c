/*
 * Copyright (c) 2013 Grzegorz Kostka (kostka.grzegorz@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <ext4_blockdev.h>
#include <ext4_config.h>
#include <ext4_errno.h>
#include <lwext4/blockdev/device_dev.h>
#include <dev/device.h>
#include <stdbool.h>

#include <libs/klibc.h>

/**@brief   Image block size.*/
#define EXT4_FILEDEV_BSIZE 512

/**@brief   Image file descriptor.*/
uint64_t device_dev_nr;

#define DROP_LINUXCACHE_BUFFERS 0

/**********************BLOCKDEV INTERFACE**************************************/
static int device_dev_open(struct ext4_blockdev *bdev);
static int device_dev_bread(struct ext4_blockdev *bdev, void *buf,
                            uint64_t blk_id, uint32_t blk_cnt);
static int device_dev_bwrite(struct ext4_blockdev *bdev, const void *buf,
                             uint64_t blk_id, uint32_t blk_cnt);
static int device_dev_close(struct ext4_blockdev *bdev);

/******************************************************************************/
EXT4_BLOCKDEV_STATIC_INSTANCE(device_dev, EXT4_FILEDEV_BSIZE, 0,
                              device_dev_open, device_dev_bread,
                              device_dev_bwrite, device_dev_close, 0, 0);

/******************************************************************************/
static int device_dev_open(struct ext4_blockdev *bdev) {
    device_dev.part_offset = 0;
    device_dev.part_size =
        device_ioctl(device_dev_nr, DEV_CMD_SECTOR_COUNT, NULL) *
        device_ioctl(device_dev_nr, DEV_CMD_SECTOR_SIZE, NULL);
    device_dev.bdif->ph_bcnt = device_dev.part_size / device_dev.bdif->ph_bsize;

    return EOK;
}

/******************************************************************************/

static int device_dev_bread(struct ext4_blockdev *bdev, void *buf,
                            uint64_t blk_id, uint32_t blk_cnt) {
    device_read(device_dev_nr, buf, blk_id * device_dev.bdif->ph_bsize,
                blk_cnt * device_dev.bdif->ph_bsize, 0);

    return EOK;
}

static void drop_cache(void) {}

/******************************************************************************/
static int device_dev_bwrite(struct ext4_blockdev *bdev, const void *buf,
                             uint64_t blk_id, uint32_t blk_cnt) {
    device_write(device_dev_nr, (void *)buf, blk_id * device_dev.bdif->ph_bsize,
                 blk_cnt * device_dev.bdif->ph_bsize, 0);

    drop_cache();
    return EOK;
}
/******************************************************************************/
static int device_dev_close(struct ext4_blockdev *bdev) { return EOK; }

/******************************************************************************/
struct ext4_blockdev *device_dev_get(void) { return &device_dev; }
/******************************************************************************/

void device_dev_name_set(const char *n) {}
/******************************************************************************/
