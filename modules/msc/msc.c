#include <libs/aether/block.h>
#include <libs/aether/stdio.h>
#include "msc.h"

#define MSC_MAX_RETRIES 3
#define MSC_CBW_DELAY_MS 5         // CBW后延迟
#define MSC_DATA_DELAY_MS 5        // 数据后延迟
#define MSC_CSW_DELAY_MS 2         // CSW前延迟
#define MSC_RESET_DELAY_MS 200     // Reset后延迟
#define MSC_CLEAR_HALT_DELAY_MS 50 // Clear HALT后延迟
#define MSC_READY_CHECK_DELAY 500  // 设备就绪检测间隔

static inline void msc_delay(uint64_t ms) {
    uint64_t ns = ms * 1000000ULL;
    uint64_t timeout = nanoTime() + ns;
    while (nanoTime() < timeout) {
        arch_pause();
    }
}

// 全局锁（防止并发访问）
static spinlock_t usb_msc_lock = SPIN_INIT;

static int msc_bulk_transfer(struct usb_pipe *pipe, void *data, size_t len,
                             bool is_read) {
    if (!pipe || !pipe->cntl) {
        printk("MSC: Invalid pipe\n");
        return -EINVAL;
    }

    if (len > 0 && !data) {
        printk("MSC: NULL data pointer for non-zero length\n");
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

// 清除端点HALT状态
static int msc_clear_endpoint_halt(usb_msc_device *dev, struct usb_pipe *pipe) {
    printk("MSC: Clearing HALT on EP 0x%02x\n", pipe->ep);

    struct usb_ctrlrequest req = {
        .bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_ENDPOINT,
        .bRequest = USB_REQ_CLEAR_FEATURE,
        .wValue = 0, // ENDPOINT_HALT feature
        .wIndex = pipe->ep,
        .wLength = 0};

    int ret = usb_send_default_control(dev->udev->defpipe, &req, NULL);
    if (ret != 0) {
        printk("MSC: Clear HALT failed: %d\n", ret);
        return -1;
    }

    msc_delay(MSC_CLEAR_HALT_DELAY_MS);
    return 0;
}

// Bulk-Only Mass Storage Reset
static int msc_reset_recovery(usb_msc_device *dev) {
    printk("MSC: Performing reset recovery\n");

    // 1. Bulk-Only Mass Storage Reset
    struct usb_ctrlrequest reset_req = {
        .bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
        .bRequest = 0xFF, // Bulk-Only Mass Storage Reset
        .wValue = 0,
        .wIndex = dev->udev->iface->bInterfaceNumber,
        .wLength = 0};

    int ret = usb_send_default_control(dev->udev->defpipe, &reset_req, NULL);
    if (ret != 0) {
        printk("MSC: Reset command failed: %d\n", ret);
        return -1;
    }

    msc_delay(20);

    // 2. Clear HALT on Bulk-In
    msc_clear_endpoint_halt(dev, dev->bulk_in);
    msc_delay(20);

    // 3. Clear HALT on Bulk-Out
    msc_clear_endpoint_halt(dev, dev->bulk_out);

    // 4. 最终延迟
    msc_delay(MSC_RESET_DELAY_MS);

    printk("MSC: Reset recovery complete\n");
    return 0;
}

static int msc_receive_csw(usb_msc_device *dev, usb_msc_csw_t *csw,
                           uint32_t expected_tag) {
    int retries = 5;

    while (retries-- > 0) {
        msc_delay(MSC_CSW_DELAY_MS);

        int ret = msc_bulk_transfer(dev->bulk_in, csw, sizeof(*csw), true);

        if (ret < 0) {
            printk("MSC: CSW recv failed, clearing HALT (retries=%d)\n",
                   retries);
            msc_clear_endpoint_halt(dev, dev->bulk_in);
            continue;
        }

        if ((size_t)ret != sizeof(*csw)) {
            printk("MSC: CSW size mismatch: %d != %lu\n", ret, sizeof(*csw));
            continue;
        }

        // 验证签名
        if (csw->dCSWSignature != 0x53425355) {
            printk("MSC: Invalid CSW signature: 0x%08x\n", csw->dCSWSignature);
            msc_delay(10);
            continue;
        }

        // 验证Tag
        if (csw->dCSWTag != expected_tag) {
            printk("MSC: CSW tag mismatch: 0x%08x != 0x%08x\n", csw->dCSWTag,
                   expected_tag);
            msc_delay(10);
            continue;
        }

        return 0; // 成功
    }

    printk("MSC: Failed to receive valid CSW\n");
    return -1;
}

static int msc_transfer(usb_msc_device *dev, void *cmd, uint8_t cmd_len,
                        void *data, size_t data_len, bool is_read) {
    usb_msc_cbw_t cbw;
    usb_msc_csw_t csw;
    int ret;

    // 参数验证
    if (!dev || !cmd || cmd_len == 0 || cmd_len > 16) {
        printk("MSC: Invalid parameters\n");
        return -EINVAL;
    }

    if (data_len > 0 && !data) {
        printk("MSC: NULL data pointer with data_len=%lu\n", data_len);
        return -EINVAL;
    }

    spin_lock(&usb_msc_lock);

    // 构建CBW
    memset(&cbw, 0, sizeof(cbw));
    cbw.dCBWSignature = 0x43425355;
    cbw.dCBWTag = (uint32_t)(nanoTime() & 0xFFFFFFFF);
    cbw.dCBWDataTransferLength = data_len;
    cbw.bmCBWFlags = (data_len > 0 && is_read) ? USB_DIR_IN : USB_DIR_OUT;
    cbw.bCBWLUN = dev->lun;
    cbw.bCBWCBLength = cmd_len;
    memcpy(cbw.CBWCB, cmd, cmd_len);

    // 发送CBW
    ret = msc_bulk_transfer(dev->bulk_out, &cbw, sizeof(cbw), false);
    if (ret < 0) {
        printk("MSC: CBW send failed\n");
        goto error;
    }

    msc_delay(MSC_CBW_DELAY_MS);

    // 数据阶段
    if (data_len > 0 && data) {
        struct usb_pipe *pipe = is_read ? dev->bulk_in : dev->bulk_out;

        ret = msc_bulk_transfer(pipe, data, data_len, is_read);
        if (ret < 0) {
            printk("MSC: Data transfer failed\n");
            goto error;
        }

        if ((size_t)ret != data_len) {
            printk("MSC: Data length mismatch: %d != %lu\n", ret, data_len);
            goto error;
        }

        msc_delay(MSC_DATA_DELAY_MS);
    }

    // 接收CSW
    ret = msc_receive_csw(dev, &csw, cbw.dCBWTag);
    if (ret != 0) {
        goto error;
    }

    // 检查CSW状态
    if (csw.bCSWStatus == 0) {
        spin_unlock(&usb_msc_lock);
        return 0; // 成功
    } else if (csw.bCSWStatus == 1) {
        printk("MSC: Command failed (CSW status=1, residue=%u)\n",
               csw.dCSWDataResidue);
        spin_unlock(&usb_msc_lock);
        return -EIO;
    } else if (csw.bCSWStatus == 2) {
        printk("MSC: Phase error\n");
        goto error;
    } else {
        printk("MSC: Unknown CSW status: %d\n", csw.bCSWStatus);
        goto error;
    }

error:
    spin_unlock(&usb_msc_lock);
    msc_reset_recovery(dev);
    return -1;
}

// 带重试的传输
static int msc_transfer_with_retry(usb_msc_device *dev, void *cmd,
                                   uint8_t cmd_len, void *data, size_t data_len,
                                   bool is_read) {
    for (int attempt = 0; attempt < MSC_MAX_RETRIES; attempt++) {
        if (attempt > 0) {
            printk("MSC: Retry %d/%d\n", attempt + 1, MSC_MAX_RETRIES);
            msc_delay(50);
        }

        int ret = msc_transfer(dev, cmd, cmd_len, data, data_len, is_read);
        if (ret == 0) {
            if (attempt > 0) {
                printk("MSC: Success after %d retries\n", attempt);
            }
            return 0;
        }
    }

    printk("MSC: Failed after %d attempts\n", MSC_MAX_RETRIES);
    return -1;
}

// READ(10)
static uint64_t msc_scsi_read_10(usb_msc_device *dev, uint64_t lba, void *buf,
                                 uint64_t count) {
    if (count > 0xFFFF || lba > 0xFFFFFFFF) {
        printk("MSC: READ(10) parameters out of range\n");
        return 0;
    }

    uint8_t cmd[10] = {0x28,
                       0,
                       (lba >> 24) & 0xFF,
                       (lba >> 16) & 0xFF,
                       (lba >> 8) & 0xFF,
                       lba & 0xFF,
                       0,
                       (count >> 8) & 0xFF,
                       count & 0xFF,
                       0};

    size_t len = count * dev->block_size;
    return (msc_transfer_with_retry(dev, cmd, 10, buf, len, true) == 0) ? count
                                                                        : 0;
}

// WRITE(10)
static uint64_t msc_scsi_write_10(usb_msc_device *dev, uint64_t lba, void *buf,
                                  uint64_t count) {
    if (count > 0xFFFF || lba > 0xFFFFFFFF) {
        printk("MSC: WRITE(10) parameters out of range\n");
        return 0;
    }

    uint8_t cmd[10] = {0x2A,
                       0,
                       (lba >> 24) & 0xFF,
                       (lba >> 16) & 0xFF,
                       (lba >> 8) & 0xFF,
                       lba & 0xFF,
                       0,
                       (count >> 8) & 0xFF,
                       count & 0xFF,
                       0};

    size_t len = count * dev->block_size;
    return (msc_transfer_with_retry(dev, cmd, 10, buf, len, false) == 0) ? count
                                                                         : 0;
}

// READ(16)
static uint64_t msc_scsi_read_16(usb_msc_device *dev, uint64_t lba, void *buf,
                                 uint64_t count) {
    if (count > 0xFFFFFFFF) {
        printk("MSC: READ(16) count too large\n");
        return 0;
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
                       (count >> 24) & 0xFF,
                       (count >> 16) & 0xFF,
                       (count >> 8) & 0xFF,
                       count & 0xFF,
                       0,
                       0};

    size_t len = count * dev->block_size;
    return (msc_transfer_with_retry(dev, cmd, 16, buf, len, true) == 0) ? count
                                                                        : 0;
}

// WRITE(16)
static uint64_t msc_scsi_write_16(usb_msc_device *dev, uint64_t lba, void *buf,
                                  uint64_t count) {
    if (count > 0xFFFFFFFF) {
        printk("MSC: WRITE(16) count too large\n");
        return 0;
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
                       (count >> 24) & 0xFF,
                       (count >> 16) & 0xFF,
                       (count >> 8) & 0xFF,
                       count & 0xFF,
                       0,
                       0};

    size_t len = count * dev->block_size;
    return (msc_transfer_with_retry(dev, cmd, 16, buf, len, false) == 0) ? count
                                                                         : 0;
}

// TEST UNIT READY
static int msc_test_unit_ready(usb_msc_device *dev) {
    uint8_t cmd[6] = {0x00, 0, 0, 0, 0, 0};
    return msc_transfer_with_retry(dev, cmd, 6, NULL, 0, true);
}

// REQUEST SENSE
static int msc_request_sense(usb_msc_device *dev, uint8_t *sense_data) {
    uint8_t cmd[6] = {0x03, 0, 0, 0, 18, 0};
    return msc_transfer_with_retry(dev, cmd, 6, sense_data, 18, true);
}

// INQUIRY
static int msc_inquiry(usb_msc_device *dev) {
    uint8_t *buf = malloc(36);
    if (!buf)
        return -1;

    memset(buf, 0, 36);
    uint8_t cmd[6] = {0x12, 0, 0, 0, 36, 0};

    int ret = msc_transfer_with_retry(dev, cmd, 6, buf, 36, true);

    if (ret == 0) {
        printk("MSC: Vendor: %.8s\n", &buf[8]);
        printk("MSC: Product: %.16s\n", &buf[16]);
        printk("MSC: Revision: %.4s\n", &buf[32]);
    }

    free(buf);
    return ret;
}

// READ CAPACITY(10)
static int msc_read_capacity_10(usb_msc_device *dev) {
    uint8_t capacity[8];
    uint8_t cmd[10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    if (msc_transfer_with_retry(dev, cmd, 10, capacity, 8, true) == 0) {
        uint32_t last_lba = be32toh(*(uint32_t *)&capacity[0]);
        uint32_t block_size = be32toh(*(uint32_t *)&capacity[4]);

        dev->block_count = (uint64_t)last_lba + 1;
        dev->block_size = block_size;

        printk("MSC: %llu blocks x %u bytes = %llu MB\n", dev->block_count,
               dev->block_size,
               (dev->block_count * dev->block_size) / (1024 * 1024));

        if (last_lba == 0xFFFFFFFF) {
            printk("MSC: Max LBA, need READ CAPACITY(16)\n");
            return -1;
        }

        return 0;
    }

    return -1;
}

// READ CAPACITY(16)
static int msc_read_capacity_16(usb_msc_device *dev) {
    uint8_t capacity[32];
    uint8_t cmd[16] = {0x9E, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0};

    if (msc_transfer_with_retry(dev, cmd, 16, capacity, 32, true) == 0) {
        uint64_t last_lba = be64toh(*(uint64_t *)&capacity[0]);
        uint32_t block_size = be32toh(*(uint32_t *)&capacity[8]);

        dev->block_count = last_lba + 1;
        dev->block_size = block_size;

        printk("MSC: %llu blocks × %u bytes = %llu MB\n", dev->block_count,
               dev->block_size,
               (dev->block_count * dev->block_size) / (1024 * 1024));

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
        printk("MSC: Read LBA out of range\n");
        return 0;
    }

    if (lba + count > dev->block_count) {
        count = dev->block_count - lba;
    }

    return dev->read_func(dev, lba, buf, count);
}

uint64_t usb_msc_write_blocks(void *dev_ptr, uint64_t lba, void *buf,
                              uint64_t count) {
    usb_msc_device *dev = (usb_msc_device *)dev_ptr;

    if (!dev || !buf || count == 0)
        return 0;

    if (lba >= dev->block_count) {
        printk("MSC: Write LBA out of range\n");
        return 0;
    }

    if (lba + count > dev->block_count) {
        count = dev->block_count - lba;
    }

    return dev->write_func(dev, lba, buf, count);
}

int usb_msc_setup(struct usbdevice_s *usbdev) {
    printk("MSC: Initializing device\n");

    usb_msc_device *dev = malloc(sizeof(usb_msc_device));
    if (!dev) {
        printk("MSC: malloc failed\n");
        return -ENOMEM;
    }

    memset(dev, 0, sizeof(*dev));
    dev->udev = usbdev;
    dev->lun = 0;
    usbdev->desc = dev;

    // 查找端点
    struct usb_endpoint_descriptor *indesc =
        usb_find_desc(usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_IN);
    struct usb_endpoint_descriptor *outdesc =
        usb_find_desc(usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_OUT);

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

    // 初始延迟
    msc_delay(100);

    // Reset
    msc_reset_recovery(dev);

    // 等待就绪
    for (int i = 0; i < 10; i++) {
        if (msc_test_unit_ready(dev) == 0) {
            printk("MSC: Device ready\n");
            break;
        }
        printk("MSC: Not ready, waiting...\n");
        msc_delay(MSC_READY_CHECK_DELAY);

        uint8_t sense[18];
        if (msc_request_sense(dev, sense) == 0) {
            printk("MSC: Sense: Key=0x%02x ASC=0x%02x ASCQ=0x%02x\n",
                   sense[2] & 0x0F, sense[12], sense[13]);
        }
    }

    // INQUIRY
    msc_inquiry(dev);

    // 默认SCSI-10
    dev->read_func = msc_scsi_read_10;
    dev->write_func = msc_scsi_write_10;
    dev->scsi_version = SCSI_VERSION_10;

    // READ CAPACITY
    if (msc_read_capacity_10(dev) != 0) {
        printk("MSC: Trying READ CAPACITY(16)\n");
        if (msc_read_capacity_16(dev) == 0) {
            dev->read_func = msc_scsi_read_16;
            dev->write_func = msc_scsi_write_16;
            dev->scsi_version = SCSI_VERSION_16;
        } else {
            printk("MSC: Both capacity commands failed\n");
            goto fail;
        }
    }

    if (dev->block_count == 0) {
        printk("MSC: Invalid capacity\n");
        goto fail;
    }

    // 注册块设备
    regist_blkdev("USB-MSC", dev, dev->block_size,
                  dev->block_count * dev->block_size, INT16_MAX,
                  usb_msc_read_blocks, usb_msc_write_blocks);

    printk("MSC: Initialized (SCSI-%d)\n", dev->scsi_version);
    set_have_usb_storage(true);

    return 0;

fail:
    if (dev) {
        usb_free_pipe(usbdev, dev->bulk_in);
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
