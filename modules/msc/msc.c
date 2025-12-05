#include <libs/aether/block.h>
#include <libs/aether/stdio.h>
#include "msc.h"

#define MSC_MAX_RETRIES 3
#define MSC_CBW_DELAY_US 100      // 减少到微秒级
#define MSC_CSW_DELAY_US 50       // 减少到微秒级
#define MSC_RESET_DELAY_MS 100    // 减少reset延迟
#define MSC_READY_CHECK_DELAY 200 // 减少就绪检测间隔

// 传输优化参数
#define MSC_MAX_TRANSFER_SIZE (128 * 1024) // 128KB per SCSI command
#define MSC_OPTIMAL_BLOCKS 256 // 每次传输256个块（128KB for 512-byte blocks）

static inline void msc_delay_us(uint64_t us) {
    uint64_t ns = us * 1000ULL;
    uint64_t timeout = nano_time() + ns;
    while (nano_time() < timeout) {
        arch_pause();
    }
}

static inline void msc_delay(uint64_t ms) { msc_delay_us(ms * 1000); }

static spinlock_t usb_msc_lock = SPIN_INIT;

static int msc_bulk_transfer(struct usb_pipe *pipe, void *data, size_t len,
                             bool is_read) {
    if (!pipe || !pipe->cntl) {
        return -EINVAL;
    }

    if (len > 0 && !data) {
        return -EINVAL;
    }

    int ret =
        usb_send_bulk(pipe, is_read ? USB_DIR_IN : USB_DIR_OUT, data, len);

    if (ret != 0) {
        printk("MSC: Bulk %s failed: ret=%d, len=%lu\n", is_read ? "IN" : "OUT",
               ret, len);
        return -EIO;
    }

    return len;
}

static int msc_clear_endpoint_halt(usb_msc_device *dev, struct usb_pipe *pipe) {
    struct usb_ctrlrequest req = {
        .bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_ENDPOINT,
        .bRequest = USB_REQ_CLEAR_FEATURE,
        .wValue = 0,
        .wIndex = pipe->ep,
        .wLength = 0};

    int ret = usb_send_default_control(dev->udev->defpipe, &req, NULL);
    if (ret != 0) {
        return -1;
    }

    msc_delay(10); // 减少延迟
    return 0;
}

static int msc_reset_recovery(usb_msc_device *dev) {
    printk("MSC: Performing reset recovery\n");

    struct usb_ctrlrequest reset_req = {
        .bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
        .bRequest = 0xFF,
        .wValue = 0,
        .wIndex = dev->iface->iface->bInterfaceNumber,
        .wLength = 0};

    int ret = usb_send_default_control(dev->udev->defpipe, &reset_req, NULL);
    if (ret != 0) {
        printk("MSC: Reset command failed: %d\n", ret);
        return -1;
    }

    msc_delay(10);
    msc_clear_endpoint_halt(dev, dev->bulk_in);
    msc_delay(10);
    msc_clear_endpoint_halt(dev, dev->bulk_out);
    msc_delay(MSC_RESET_DELAY_MS);

    return 0;
}

static int msc_receive_csw(usb_msc_device *dev, usb_msc_csw_t *csw,
                           uint32_t expected_tag) {
    int retries = 3; // 减少重试次数

    while (retries-- > 0) {
        // 只在第一次尝试时不延迟，后续重试才延迟
        if (retries < 2) {
            msc_delay_us(MSC_CSW_DELAY_US);
        }

        int ret = msc_bulk_transfer(dev->bulk_in, csw, sizeof(*csw), true);

        if (ret < 0) {
            if (retries > 0) {
                msc_clear_endpoint_halt(dev, dev->bulk_in);
            }
            continue;
        }

        if ((size_t)ret != sizeof(*csw)) {
            continue;
        }

        if (csw->dCSWSignature != 0x53425355) {
            printk("MSC: Invalid CSW signature: 0x%08x\n", csw->dCSWSignature);
            continue;
        }

        if (csw->dCSWTag != expected_tag) {
            printk("MSC: CSW tag mismatch: 0x%08x != 0x%08x\n", csw->dCSWTag,
                   expected_tag);
            continue;
        }

        return 0;
    }

    printk("MSC: Failed to receive valid CSW\n");
    return -1;
}

static int msc_transfer(usb_msc_device *dev, void *cmd, uint8_t cmd_len,
                        void *data, size_t data_len, bool is_read) {
    usb_msc_cbw_t cbw;
    usb_msc_csw_t csw;
    int ret;

    if (!dev || !cmd || cmd_len == 0 || cmd_len > 16) {
        return -EINVAL;
    }

    if (data_len > 0 && !data) {
        return -EINVAL;
    }

    memset(&cbw, 0, sizeof(cbw));
    memset(&csw, 0, sizeof(csw));

    spin_lock(&usb_msc_lock);

    // 构建CBW
    cbw.dCBWSignature = 0x43425355;
    cbw.dCBWTag = (uint32_t)(nano_time() & 0xFFFFFFFF);
    cbw.dCBWDataTransferLength = data_len;
    cbw.bmCBWFlags = (data_len > 0 && is_read) ? USB_DIR_IN : USB_DIR_OUT;
    cbw.bCBWLUN = dev->lun;
    cbw.bCBWCBLength = cmd_len;
    memcpy(cbw.CBWCB, cmd, cmd_len);

    // 发送CBW
    ret = msc_bulk_transfer(dev->bulk_out, &cbw, sizeof(cbw), false);
    if (ret < 0) {
        goto error;
    }

    // 减少延迟
    if (data_len > 0) {
        msc_delay_us(MSC_CBW_DELAY_US);
    }

    // 数据阶段
    if (data_len > 0 && data) {
        struct usb_pipe *pipe = is_read ? dev->bulk_in : dev->bulk_out;

        ret = msc_bulk_transfer(pipe, data, data_len, is_read);
        if (ret < 0) {
            goto error;
        }

        if ((size_t)ret != data_len) {
            printk("MSC: Data length mismatch: %d != %lu\n", ret, data_len);
            goto error;
        }
    }

    // 接收CSW（不需要额外延迟，CSW接收函数内部会处理）
    ret = msc_receive_csw(dev, &csw, cbw.dCBWTag);
    if (ret != 0) {
        goto error;
    }

    spin_unlock(&usb_msc_lock);

    // 检查CSW状态
    if (csw.bCSWStatus == 0) {
        return 0;
    } else if (csw.bCSWStatus == 1) {
        printk("MSC: Command failed (CSW status=1)\n");
        return -EIO;
    } else if (csw.bCSWStatus == 2) {
        printk("MSC: Phase error\n");
        msc_reset_recovery(dev);
        return -EIO;
    } else {
        printk("MSC: Unknown CSW status: %d\n", csw.bCSWStatus);
        return -EIO;
    }

error:
    spin_unlock(&usb_msc_lock);
    msc_reset_recovery(dev);
    return -1;
}

static int msc_transfer_with_retry(usb_msc_device *dev, void *cmd,
                                   uint8_t cmd_len, void *data, size_t data_len,
                                   bool is_read) {
    for (int attempt = 0; attempt < MSC_MAX_RETRIES; attempt++) {
        if (attempt > 0) {
            printk("MSC: Retry %d/%d\n", attempt + 1, MSC_MAX_RETRIES);
            msc_delay(20); // 减少重试延迟
        }

        int ret = msc_transfer(dev, cmd, cmd_len, data, data_len, is_read);
        if (ret == 0) {
            return 0;
        }

        // 如果是EIO（命令失败），不要重试
        if (ret == -EIO) {
            return ret;
        }
    }

    return -1;
}

static uint64_t msc_scsi_read_10(usb_msc_device *dev, uint64_t lba, void *buf,
                                 uint64_t count) {
    if (lba > 0xFFFFFFFF) {
        return 0;
    }

    uint64_t total_read = 0;
    uint8_t *buffer = (uint8_t *)buf;

    while (count > 0) {
        // 每次传输的块数（不超过65535块，且考虑传输大小限制）
        uint64_t blocks_to_read = count;
        size_t max_blocks = MSC_MAX_TRANSFER_SIZE / dev->block_size;

        if (blocks_to_read > max_blocks) {
            blocks_to_read = max_blocks;
        }
        if (blocks_to_read > 0xFFFF) {
            blocks_to_read = 0xFFFF;
        }

        uint8_t cmd[10] = {0x28,
                           0,
                           (lba >> 24) & 0xFF,
                           (lba >> 16) & 0xFF,
                           (lba >> 8) & 0xFF,
                           lba & 0xFF,
                           0,
                           (blocks_to_read >> 8) & 0xFF,
                           blocks_to_read & 0xFF,
                           0};

        size_t len = blocks_to_read * dev->block_size;

        if (msc_transfer_with_retry(dev, cmd, 10, buffer, len, true) != 0) {
            break;
        }

        total_read += blocks_to_read;
        buffer += len;
        lba += blocks_to_read;
        count -= blocks_to_read;
    }

    return total_read;
}

static uint64_t msc_scsi_write_10(usb_msc_device *dev, uint64_t lba, void *buf,
                                  uint64_t count) {
    if (lba > 0xFFFFFFFF) {
        return 0;
    }

    uint64_t total_written = 0;
    uint8_t *buffer = (uint8_t *)buf;

    while (count > 0) {
        uint64_t blocks_to_write = count;
        size_t max_blocks = MSC_MAX_TRANSFER_SIZE / dev->block_size;

        if (blocks_to_write > max_blocks) {
            blocks_to_write = max_blocks;
        }
        if (blocks_to_write > 0xFFFF) {
            blocks_to_write = 0xFFFF;
        }

        uint8_t cmd[10] = {0x2A,
                           0,
                           (lba >> 24) & 0xFF,
                           (lba >> 16) & 0xFF,
                           (lba >> 8) & 0xFF,
                           lba & 0xFF,
                           0,
                           (blocks_to_write >> 8) & 0xFF,
                           blocks_to_write & 0xFF,
                           0};

        size_t len = blocks_to_write * dev->block_size;

        if (msc_transfer_with_retry(dev, cmd, 10, buffer, len, false) != 0) {
            break;
        }

        total_written += blocks_to_write;
        buffer += len;
        lba += blocks_to_write;
        count -= blocks_to_write;
    }

    return total_written;
}

static uint64_t msc_scsi_read_16(usb_msc_device *dev, uint64_t lba, void *buf,
                                 uint64_t count) {
    uint64_t total_read = 0;
    uint8_t *buffer = (uint8_t *)buf;

    while (count > 0) {
        uint64_t blocks_to_read = count;
        size_t max_blocks = MSC_MAX_TRANSFER_SIZE / dev->block_size;

        if (blocks_to_read > max_blocks) {
            blocks_to_read = max_blocks;
        }
        if (blocks_to_read > 0xFFFFFFFF) {
            blocks_to_read = 0xFFFFFFFF;
        }

        uint8_t cmd[16] = {0x88,
                           0,
                           (lba >> 56) & 0xFF,
                           (lba >> 48) & 0xFF,
                           (lba >> 40) & 0xFF,
                           (lba >> 32) & 0xFF,
                           (lba >> 24) & 0xFF,
                           (lba >> 16) & 0xFF,
                           (lba >> 8) & 0xFF,
                           lba & 0xFF,
                           (blocks_to_read >> 24) & 0xFF,
                           (blocks_to_read >> 16) & 0xFF,
                           (blocks_to_read >> 8) & 0xFF,
                           blocks_to_read & 0xFF,
                           0,
                           0};

        size_t len = blocks_to_read * dev->block_size;

        if (msc_transfer_with_retry(dev, cmd, 16, buffer, len, true) != 0) {
            break;
        }

        total_read += blocks_to_read;
        buffer += len;
        lba += blocks_to_read;
        count -= blocks_to_read;
    }

    return total_read;
}

static uint64_t msc_scsi_write_16(usb_msc_device *dev, uint64_t lba, void *buf,
                                  uint64_t count) {
    uint64_t total_written = 0;
    uint8_t *buffer = (uint8_t *)buf;

    while (count > 0) {
        uint64_t blocks_to_write = count;
        size_t max_blocks = MSC_MAX_TRANSFER_SIZE / dev->block_size;

        if (blocks_to_write > max_blocks) {
            blocks_to_write = max_blocks;
        }
        if (blocks_to_write > 0xFFFFFFFF) {
            blocks_to_write = 0xFFFFFFFF;
        }

        uint8_t cmd[16] = {0x8A,
                           0,
                           (lba >> 56) & 0xFF,
                           (lba >> 48) & 0xFF,
                           (lba >> 40) & 0xFF,
                           (lba >> 32) & 0xFF,
                           (lba >> 24) & 0xFF,
                           (lba >> 16) & 0xFF,
                           (lba >> 8) & 0xFF,
                           lba & 0xFF,
                           (blocks_to_write >> 24) & 0xFF,
                           (blocks_to_write >> 16) & 0xFF,
                           (blocks_to_write >> 8) & 0xFF,
                           blocks_to_write & 0xFF,
                           0,
                           0};

        size_t len = blocks_to_write * dev->block_size;

        if (msc_transfer_with_retry(dev, cmd, 16, buffer, len, false) != 0) {
            break;
        }

        total_written += blocks_to_write;
        buffer += len;
        lba += blocks_to_write;
        count -= blocks_to_write;
    }

    return total_written;
}

static int msc_test_unit_ready(usb_msc_device *dev) {
    uint8_t cmd[6] = {0x00, 0, 0, 0, 0, 0};
    return msc_transfer_with_retry(dev, cmd, 6, NULL, 0, true);
}

static int msc_request_sense(usb_msc_device *dev, uint8_t *sense_data) {
    uint8_t cmd[6] = {0x03, 0, 0, 0, 18, 0};
    return msc_transfer_with_retry(dev, cmd, 6, sense_data, 18, true);
}

static int msc_inquiry(usb_msc_device *dev) {
    uint8_t buf[36];

    memset(buf, 0, sizeof(buf));
    uint8_t cmd[6] = {0x12, 0, 0, 0, 36, 0};

    int ret = msc_transfer_with_retry(dev, cmd, 6, buf, 36, true);

    if (ret == 0) {
        printk("MSC: Vendor: %.8s\n", &buf[8]);
        printk("MSC: Product: %.16s\n", &buf[16]);
        printk("MSC: Revision: %.4s\n", &buf[32]);
    }

    return ret;
}

static int msc_read_capacity_10(usb_msc_device *dev) {
    uint8_t capacity[8];
    uint8_t cmd[10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    if (msc_transfer_with_retry(dev, cmd, 10, capacity, 8, true) == 0) {
        uint32_t last_lba = be32toh(*(uint32_t *)&capacity[0]);
        uint32_t block_size = be32toh(*(uint32_t *)&capacity[4]);

        dev->block_count = (uint64_t)last_lba + 1;
        dev->block_size = block_size;

        if (last_lba == 0xFFFFFFFF) {
            return -1;
        }

        return 0;
    }

    return -1;
}

static int msc_read_capacity_16(usb_msc_device *dev) {
    uint8_t capacity[32];
    uint8_t cmd[16] = {0x9E, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0};

    if (msc_transfer_with_retry(dev, cmd, 16, capacity, 32, true) == 0) {
        uint64_t last_lba = be64toh(*(uint64_t *)&capacity[0]);
        uint32_t block_size = be32toh(*(uint32_t *)&capacity[8]);

        dev->block_count = last_lba + 1;
        dev->block_size = block_size;

        return 0;
    }

    return -1;
}

uint64_t usb_msc_read_blocks(void *dev_ptr, uint64_t lba, void *buf,
                             uint64_t count) {
    usb_msc_device *dev = (usb_msc_device *)dev_ptr;

    if (!dev || !buf || count == 0)
        return 0;

    if (lba >= dev->block_count) {
        return 0;
    }

    if (lba + count > dev->block_count) {
        count = dev->block_count - lba;
    }

    if (lba > 0xFFFFFFFF) {
        return msc_scsi_read_16(dev, lba, buf, count);
    } else {
        return msc_scsi_read_10(dev, lba, buf, count);
    }
}

uint64_t usb_msc_write_blocks(void *dev_ptr, uint64_t lba, void *buf,
                              uint64_t count) {
    usb_msc_device *dev = (usb_msc_device *)dev_ptr;

    if (!dev || !buf || count == 0)
        return 0;

    if (lba >= dev->block_count) {
        return 0;
    }

    if (lba + count > dev->block_count) {
        count = dev->block_count - lba;
    }

    if (lba > 0xFFFFFFFF) {
        return msc_scsi_write_16(dev, lba, buf, count);
    } else {
        return msc_scsi_write_10(dev, lba, buf, count);
    }
}

int usb_msc_setup(struct usbdevice_s *usbdev,
                  struct usbdevice_a_interface *iface) {
    printk("MSC: Initializing device\n");

    usb_msc_device *dev = malloc(sizeof(usb_msc_device));
    if (!dev) {
        printk("MSC: malloc failed\n");
        return -ENOMEM;
    }

    memset(dev, 0, sizeof(*dev));
    dev->udev = usbdev;
    dev->iface = iface;
    dev->lun = 0;
    usbdev->desc = dev;

    struct usb_endpoint_descriptor *indesc =
        usb_find_desc(iface, USB_ENDPOINT_XFER_BULK, USB_DIR_IN);
    struct usb_endpoint_descriptor *outdesc =
        usb_find_desc(iface, USB_ENDPOINT_XFER_BULK, USB_DIR_OUT);

    if (!indesc || !outdesc) {
        printk("MSC: Endpoints not found\n");
        goto fail;
    }

    dev->bulk_in = usb_alloc_pipe(usbdev, indesc);
    dev->bulk_out = usb_alloc_pipe(usbdev, outdesc);

    if (!dev->bulk_in || !dev->bulk_out) {
        printk("MSC: Pipe allocation failed\n");
        goto fail;
    }

    printk("MSC: IN=0x%02x (max=%d), OUT=0x%02x (max=%d)\n", dev->bulk_in->ep,
           dev->bulk_in->maxpacket, dev->bulk_out->ep,
           dev->bulk_out->maxpacket);

    // 减少初始延迟
    msc_delay(50);

    // 等待就绪
    for (int i = 0; i < 10; i++) {
        if (msc_test_unit_ready(dev) == 0) {
            printk("MSC: Device ready\n");
            break;
        }

        uint8_t sense[18];
        if (msc_request_sense(dev, sense) == 0) {
            uint8_t key = sense[2] & 0x0F;
            uint8_t asc = sense[12];

            // 如果是 NOT READY 但正在变为就绪，继续等待
            if (key == 0x02 && asc == 0x04) {
                printk("MSC: Device becoming ready...\n");
                msc_delay(MSC_READY_CHECK_DELAY);
                continue;
            }
        }

        msc_delay(MSC_READY_CHECK_DELAY);
    }

    msc_inquiry(dev);

    // 先尝试 READ CAPACITY(10)
    if (msc_read_capacity_10(dev) != 0) {
        printk("MSC: Trying READ CAPACITY(16)\n");
        if (msc_read_capacity_16(dev) != 0) {
            printk("MSC: Both capacity commands failed\n");
            goto fail;
        }
    }

    if (dev->block_count == 0) {
        printk("MSC: Invalid capacity\n");
        goto fail;
    }

    // 使用更大的最大传输大小
    regist_blkdev("USB-MSC", dev, dev->block_size,
                  dev->block_count * dev->block_size,
                  MSC_MAX_TRANSFER_SIZE, // 使用128KB
                  usb_msc_read_blocks, usb_msc_write_blocks);

    printk("MSC: Device initialized successfully\n");
    return 0;

fail:
    if (dev) {
        if (dev->bulk_in)
            usb_free_pipe(usbdev, dev->bulk_in);
        if (dev->bulk_out)
            usb_free_pipe(usbdev, dev->bulk_out);
        free(dev);
    }
    return -1;
}

int usb_msc_remove(struct usbdevice_s *usbdev) {
    if (usbdev && usbdev->desc) {
        usb_msc_device *dev = (usb_msc_device *)usbdev->desc;
        usb_free_pipe(usbdev, dev->bulk_in);
        usb_free_pipe(usbdev, dev->bulk_out);
        free(dev);
        usbdev->desc = NULL;
    }
    return 0;
}

usb_driver_t msc_driver = {
    .class = USB_CLASS_MASS_STORAGE,
    .subclass = 0,
    .probe = usb_msc_setup,
    .remove = usb_msc_remove,
};

__attribute__((visibility("default"))) int dlmain() {
    regist_usb_driver(&msc_driver);
    return 0;
}
