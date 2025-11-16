#include <libs/aether/block.h>
#include <libs/aether/stdio.h>
#include "msc.h"

static inline void delay(uint64_t ms) {
    uint64_t ns = ms * 1000000ULL;
    uint64_t timeout = nanoTime() + ns;
    while (nanoTime() < timeout) {
        arch_pause();
    }
}

spinlock_t usb_bulk_transfer_lock = SPIN_INIT;

int usb_bulk_transfer(struct usb_pipe *pipe, void *data, size_t len,
                      bool is_read) {
    if (!pipe || !pipe->cntl)
        return -EINVAL;

    spin_lock(&usb_bulk_transfer_lock);

    int ret = (usb_send_bulk(pipe, is_read ? USB_DIR_IN : USB_DIR_OUT, data,
                             len) == 0)
                  ? len
                  : -EIO;

    spin_unlock(&usb_bulk_transfer_lock);

    return ret;
}

// 重置USB MSC设备端点
static int usb_msc_reset_recovery(usb_msc_device *dev) {
    printk("USB MSC: Performing reset recovery\n");

    // 1. Bulk-Only Mass Storage Reset
    struct usb_ctrlrequest req = {.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS |
                                                  USB_RECIP_INTERFACE,
                                  .bRequest = 0xFF,
                                  .wValue = 0,
                                  .wIndex = dev->udev->iface->bInterfaceNumber,
                                  .wLength = 0};

    int ret = usb_send_default_control(dev->udev->defpipe, &req, NULL);
    if (ret != 0) {
        printk("USB MSC: Reset recovery failed: %d\n", ret);
        return -1;
    }

    // 2. Clear Feature HALT to Bulk-In endpoint
    struct usb_ctrlrequest clear_in = {
        .bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_ENDPOINT,
        .bRequest = USB_REQ_CLEAR_FEATURE, // 0x01
        .wValue = 0,                       // ENDPOINT_HALT
        .wIndex = dev->bulk_in->ep,
        .wLength = 0};
    usb_send_default_control(dev->udev->defpipe, &clear_in, NULL);

    // 3. Clear Feature HALT to Bulk-Out endpoint
    struct usb_ctrlrequest clear_out = {
        .bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_ENDPOINT,
        .bRequest = USB_REQ_CLEAR_FEATURE,
        .wValue = 0,
        .wIndex = dev->bulk_out->ep,
        .wLength = 0};
    usb_send_default_control(dev->udev->defpipe, &clear_out, NULL);

    delay(100); // 或其他延迟函数

    return 0;
}

spinlock_t usb_msc_transfer_lock = SPIN_INIT;

static int usb_msc_transfer(usb_msc_device *dev, void *cmd, uint8_t cmd_length,
                            void *data, size_t data_len, bool is_read) {
    int max_retries = 3; // 最多重试 3 次
    int attempt;

    for (attempt = 0; attempt < max_retries; attempt++) {
        if (attempt > 0) {
            // 在重试前执行 reset recovery
            if (usb_msc_reset_recovery(dev) != 0) {
                printk("USB MSC: Reset recovery failed, aborting\n");
                return -1;
            }
        }

        spin_lock(&usb_msc_transfer_lock);

        // 发送 CBW
        usb_msc_cbw_t cbw;
        memset(&cbw, 0, sizeof(usb_msc_cbw_t));
        cbw.dCBWSignature = 0x43425355;
        cbw.dCBWTag =
            (uint32_t)(nanoTime() & 0xFFFFFFFF); // 使用时间戳作为唯一 Tag
        cbw.dCBWDataTransferLength = data_len;
        cbw.bmCBWFlags = is_read ? USB_DIR_IN : USB_DIR_OUT;
        cbw.bCBWLUN = dev->lun;
        cbw.bCBWCBLength = cmd_length;

        memcpy(cbw.CBWCB, cmd, cmd_length);

        if (usb_bulk_transfer(dev->bulk_out, &cbw, sizeof(cbw), false) < 0) {
            spin_unlock(&usb_msc_transfer_lock);
            printk("USB MSC: Failed to transfer CBW (attempt %d)\n",
                   attempt + 1);
            continue; // 重试
        }

        // 数据传输
        bool data_transfer_ok = true;
        if (data_len > 0) {
            struct usb_pipe *pipe = is_read ? dev->bulk_in : dev->bulk_out;
            int data_ret = usb_bulk_transfer(pipe, data, data_len, is_read);

            if (data_ret < 0) {
                printk("USB MSC: Failed to transfer data\n", attempt + 1);
                data_transfer_ok = false;
            } else if ((size_t)data_ret != data_len) {
                printk("USB MSC: Data transfer incomplete: expected %zu, got "
                       "%d bytes\n",
                       data_len, data_ret, attempt + 1);
                data_transfer_ok = false;
            }

            if (!data_transfer_ok) {
                spin_unlock(&usb_msc_transfer_lock);
                continue; // 重试
            }
        }

        // 接收 CSW
        usb_msc_csw_t csw;
        int csw_retries = 3;
        int csw_ret = -1;
        bool csw_valid = false;

        while (csw_retries-- > 0) {
            csw_ret = usb_bulk_transfer(dev->bulk_in, &csw, sizeof(csw), true);

            if (csw_ret < 0) {
                // 尝试清除端点 STALL
                struct usb_ctrlrequest clear_halt = {
                    .bRequestType =
                        USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_ENDPOINT,
                    .bRequest = USB_REQ_CLEAR_FEATURE,
                    .wValue = 0,
                    .wIndex = dev->bulk_in->ep,
                    .wLength = 0};
                usb_send_default_control(dev->udev->defpipe, &clear_halt, NULL);
                delay(10);
                continue;
            }

            // 验证 CSW 签名
            if (csw.dCSWSignature != 0x53425355) {
                printk("USB MSC: Invalid CSW signature: 0x%08x (attempt %d)\n",
                       csw.dCSWSignature, attempt + 1);
                continue;
            }

            // 验证 CSW Tag 是否匹配
            if (csw.dCSWTag != cbw.dCBWTag) {
                printk("USB MSC: CSW tag mismatch: got %u, expected %u "
                       "(attempt %d)\n",
                       csw.dCSWTag, cbw.dCBWTag, attempt + 1);
                continue;
            }

            csw_valid = true;
            break;
        }

        if (!csw_valid || csw_ret < 0) {
            spin_unlock(&usb_msc_transfer_lock);
            printk("USB MSC: CSW transfer/validation failed after retries "
                   "(attempt %d)\n",
                   attempt + 1);
            continue; // 重试整个传输
        }

        // 检查 CSW 状态
        if (csw.bCSWStatus == 0) {
            spin_unlock(&usb_msc_transfer_lock);
            if (attempt > 0) {
                printk("USB MSC: Transfer succeeded after %d retries\n",
                       attempt);
            }
            return 0; // 成功！
        }

        // CSW 状态非 0（命令失败）
        printk("USB MSC: Transfer failed with CSW status: %d, residue: %u "
               "(attempt %d)\n",
               csw.bCSWStatus, csw.dCSWDataResidue, attempt + 1);

        spin_unlock(&usb_msc_transfer_lock);

        // 如果是 Phase Error (状态 2)，必须 reset
        if (csw.bCSWStatus == 2) {
            printk("USB MSC: Phase error detected, forcing reset\n");
            continue; // 重试
        }

        // 如果是 Command Failed (状态 1)，可能是逻辑错误，不一定重试有用
        if (csw.bCSWStatus == 1) {
            printk("USB MSC: Command failed (may be logical error)\n");
            // 这里仍然尝试重试一次
            if (attempt == 0) {
                continue;
            } else {
                return -1; // 多次失败，放弃
            }
        }
    }

    printk("USB MSC: Transfer failed after %d attempts\n", max_retries);
    return -1;
}

// SCSI 10命令格式
static int usb_msc_read_10(usb_msc_device *dev, uint64_t lba, void *buf,
                           uint64_t count) {
    uint8_t cmd[16] = {SCSI_READ_10,
                       0,
                       (lba >> 24) & 0xFF,
                       (lba >> 16) & 0xFF,
                       (lba >> 8) & 0xFF,
                       lba & 0xFF,
                       0,
                       (count >> 8) & 0xFF,
                       count & 0xFF,
                       0};

    return usb_msc_transfer(dev, cmd, 10, buf, count * dev->block_size, true) ==
                   0
               ? count
               : 0;
}

static int usb_msc_write_10(usb_msc_device *dev, uint64_t lba, void *buf,
                            uint64_t count) {
    uint8_t cmd[16] = {SCSI_WRITE_10,
                       0,
                       (lba >> 24) & 0xFF,
                       (lba >> 16) & 0xFF,
                       (lba >> 8) & 0xFF,
                       lba & 0xFF,
                       0,
                       (count >> 8) & 0xFF,
                       count & 0xFF,
                       0};

    return usb_msc_transfer(dev, cmd, 10, buf, count * dev->block_size,
                            false) == 0
               ? count
               : 0;
}

// SCSI 12命令格式
static int usb_msc_read_12(usb_msc_device *dev, uint64_t lba, void *buf,
                           uint64_t count) {
    uint8_t cmd[16] = {SCSI_READ_12,
                       0,
                       (lba >> 24) & 0xFF,
                       (lba >> 16) & 0xFF,
                       (lba >> 8) & 0xFF,
                       lba & 0xFF,
                       (count >> 24) & 0xFF,
                       (count >> 16) & 0xFF,
                       (count >> 8) & 0xFF,
                       count & 0xFF,
                       0};

    return usb_msc_transfer(dev, cmd, 12, buf, count * dev->block_size, true) ==
                   0
               ? count
               : 0;
}

static int usb_msc_write_12(usb_msc_device *dev, uint64_t lba, void *buf,
                            uint64_t count) {
    uint8_t cmd[16] = {SCSI_WRITE_12,
                       0,
                       (lba >> 24) & 0xFF,
                       (lba >> 16) & 0xFF,
                       (lba >> 8) & 0xFF,
                       lba & 0xFF,
                       (count >> 24) & 0xFF,
                       (count >> 16) & 0xFF,
                       (count >> 8) & 0xFF,
                       count & 0xFF,
                       0};

    return usb_msc_transfer(dev, cmd, 12, buf, count * dev->block_size,
                            false) == 0
               ? count
               : 0;
}

// SCSI 16命令格式
static int usb_msc_read_16(usb_msc_device *dev, uint64_t lba, void *buf,
                           uint64_t count) {
    uint8_t cmd[16] = {
        SCSI_READ_16,
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
        0,
    };

    return usb_msc_transfer(dev, cmd, 16, buf, count * dev->block_size, true) ==
                   0
               ? count
               : 0;
}

static int usb_msc_write_16(usb_msc_device *dev, uint64_t lba, void *buf,
                            uint64_t count) {
    uint8_t cmd[16] = {
        SCSI_WRITE_16,
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
        0,
    };

    return usb_msc_transfer(dev, cmd, 16, buf, count * dev->block_size,
                            false) == 0
               ? count
               : 0;
}

// SCSI INQUIRY 基本数据（36字节，标准）
typedef struct {
    uint8_t peripheral_device_type;     // 0
    uint8_t removable;                  // 1
    uint8_t version;                    // 2
    uint8_t response_data_format;       // 3
    uint8_t additional_length;          // 4
    uint8_t reserved[3];                // 5-7
    uint8_t vendor_identification[8];   // 8-15
    uint8_t product_identification[16]; // 16-31
    uint8_t product_revision_level[4];  // 32-35
} __attribute__((packed)) scsi_inquiry_data_t;

static int usb_msc_detect_scsi_capability(usb_msc_device *dev) {
    printk("[USB MSC]: Starting SCSI capability detection\n");

    // 默认使用SCSI-10
    dev->read_func = usb_msc_read_10;
    dev->write_func = usb_msc_write_10;
    dev->scsi_version = SCSI_VERSION_10;

    // 分配足够大的缓冲区（但只请求需要的部分）
    uint8_t *inquiry_buf = malloc(255); // 255字节缓冲区
    if (!inquiry_buf) {
        printk("[USB MSC]: Failed to allocate inquiry buffer\n");
        return -1;
    }

    memset(inquiry_buf, 0, 255);

    // 标准INQUIRY（36字节）
    uint8_t inquiry_cmd[6] = {
        SCSI_INQUIRY, // 0x12
        0,            // EVPD = 0
        0,            // Page Code = 0
        0,            // Allocation Length MSB
        36,           // Allocation Length LSB (36字节)
        0             // Control
    };

    int ret = usb_msc_transfer(dev, inquiry_cmd, 6, inquiry_buf, 36, true);

    if (ret != 0) {
        printk("[USB MSC]: Standard INQUIRY failed\n");
        free(inquiry_buf);
        return -1; // 标准INQUIRY失败是严重问题
    }

    // 解析INQUIRY数据
    scsi_inquiry_data_t *inquiry_data = (scsi_inquiry_data_t *)inquiry_buf;

    printk("[USB MSC]: Device Vendor: %.8s\n",
           inquiry_data->vendor_identification);
    printk("[USB MSC]: Product: %.16s\n", inquiry_data->product_identification);
    printk("[USB MSC]: Revision: %.4s\n", inquiry_data->product_revision_level);

    uint8_t scsi_version = inquiry_data->version;
    printk("[USB MSC]: SCSI Version: 0x%02X\n", scsi_version);

    // 根据SCSI版本选择命令集（保守策略）
    if (scsi_version >= 0x06) {
        // SPC-5或更高 - 尝试SCSI-16
        printk("[USB MSC]: Attempting SCSI-16 (SPC-5+)\n");

        // 测试READ CAPACITY(16)来验证支持
        uint8_t cap16_buf[32];
        uint8_t cap16_cmd[16] = {
            0x9E, // SERVICE ACTION IN(16) / READ CAPACITY(16)
            0x10, // Service Action = 0x10
            0,    0, 0, 0,  0, 0, 0, 0, // LBA = 0
            0,    0, 0, 32,             // Allocation Length = 32
            0,                          // PMI = 0
            0                           // Control
        };

        if (usb_msc_transfer(dev, cap16_cmd, 16, cap16_buf, 32, true) == 0) {
            dev->read_func = usb_msc_read_16;
            dev->write_func = usb_msc_write_16;
            dev->scsi_version = SCSI_VERSION_16;
            printk("[USB MSC]: Using SCSI-16\n");
        } else {
            printk("[USB MSC]: READ CAPACITY(16) failed, falling back to "
                   "SCSI-10\n");
        }
    } else if (scsi_version >= 0x03) {
        // SPC-2/SPC-3 - 使用SCSI-10（更安全）
        printk("[USB MSC]: Using SCSI-10 (SPC-2/SPC-3)\n");
    } else {
        // SPC或更早 - 使用SCSI-10
        printk("[USB MSC]: Using SCSI-10 (legacy)\n");
    }

    free(inquiry_buf);
    return 0;
}

uint64_t usb_msc_read_blocks(void *dev, uint64_t lba, void *buf,
                             uint64_t count) {
    usb_msc_device *msc_dev = (usb_msc_device *)dev;
    return msc_dev->read_func(msc_dev, lba, buf, count);
}

uint64_t usb_msc_write_blocks(void *dev, uint64_t lba, void *buf,
                              uint64_t count) {
    usb_msc_device *msc_dev = (usb_msc_device *)dev;
    return msc_dev->write_func(msc_dev, lba, buf, count);
}

int usb_msc_setup(struct usbdevice_s *usbdev) {
    usb_msc_device *dev = malloc(sizeof(usb_msc_device));
    if (!dev)
        return -ENOMEM;

    memset(dev, 0, sizeof(usb_msc_device));
    dev->udev = usbdev;
    dev->lun = 0;

    usbdev->desc = dev;

    struct usb_pipe *inpipe = NULL, *outpipe = NULL;
    struct usb_endpoint_descriptor *indesc =
        usb_find_desc(usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_IN);
    struct usb_endpoint_descriptor *outdesc =
        usb_find_desc(usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_OUT);

    if (!indesc || !outdesc)
        goto fail;

    inpipe = usb_alloc_pipe(usbdev, indesc);
    outpipe = usb_alloc_pipe(usbdev, outdesc);

    if (!inpipe || !outpipe)
        goto fail;

    dev->bulk_in = inpipe;
    dev->bulk_out = outpipe;

    printk("MSC: Detecting scsi capability...\n");

    usb_msc_detect_scsi_capability(dev);

    uint8_t test_cmd[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int ret = 0;
    do {
        ret = usb_msc_transfer(dev, test_cmd, 6, NULL, 0, true);
    } while (ret != 0);

    uint8_t capacity[8];
    uint8_t cmd[16] = {SCSI_READ_CAPACITY_10};
    if (usb_msc_transfer(dev, cmd, 10, capacity, sizeof(capacity), true) == 0) {
        dev->block_count = be32toh(*(uint32_t *)capacity) + 1;
        dev->block_size = be32toh(*(uint32_t *)(capacity + 4));
    } else {
        dev->block_size = 512;
        dev->block_count = UINT64_MAX / 512;
    }

    printk("MSC: block size %d, block count %d\n", dev->block_size,
           dev->block_count);

    regist_blkdev("MSC", dev, dev->block_size,
                  dev->block_count * dev->block_size, INT16_MAX,
                  usb_msc_read_blocks, usb_msc_write_blocks);

    set_have_usb_storage(true);

    return 0;

fail:
    printk("Failed initialize mass storage device!!!\n");

    usb_free_pipe(usbdev, inpipe);
    usb_free_pipe(usbdev, outpipe);
    free(dev);
    return -1;
}

int usb_msc_remove(struct usbdevice_s *usbdev) { return 0; }

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
