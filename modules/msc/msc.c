// msc.c
#include "msc.h"
#include <libs/aether/mm.h>

// 全局 MSC 设备列表
static usb_msc_device_t *msc_devices = NULL;

// 发送 Command Block Wrapper
int msc_send_cbw(usb_msc_device_t *msc, usb_msc_cbw_t *cbw) {
    if (!msc || !cbw) {
        return -1;
    }

    int ret =
        usb_bulk_transfer(msc->usb_device, msc->bulk_out_ep, (uint8_t *)cbw,
                          sizeof(usb_msc_cbw_t), NULL, NULL);

    if (ret < 0) {
        return ret;
    }

    return 0;
}

// 接收 Command Status Wrapper
int msc_receive_csw(usb_msc_device_t *msc, usb_msc_csw_t *csw) {
    if (!msc || !csw) {
        return -1;
    }

    memset(csw, 0, sizeof(usb_msc_csw_t));

    int ret =
        usb_bulk_transfer(msc->usb_device, msc->bulk_in_ep, (uint8_t *)csw,
                          sizeof(usb_msc_csw_t), NULL, NULL);

    if (ret < 0) {
        return ret;
    }

    // 验证 CSW
    if (csw->signature != CSW_SIGNATURE) {
        printk("MSC: Invalid CSW signature: 0x%08x\n", csw->signature);
        return -1;
    }

    return csw->status;
}

spinlock_t msc_transfer_lock = {0};

// 执行 MSC 传输
int msc_transfer(usb_msc_device_t *msc, uint8_t *cb, uint8_t cb_len, void *data,
                 uint32_t data_len, bool data_in) {
    if (!msc || !cb) {
        return -1;
    }

    usb_msc_cbw_t cbw;
    usb_msc_csw_t csw;

    // 准备 CBW
    memset(&cbw, 0, sizeof(cbw));
    cbw.signature = CBW_SIGNATURE;
    cbw.tag = ++msc->tag;
    cbw.data_length = data_len;
    cbw.flags = data_in ? CBW_FLAGS_DATA_IN : CBW_FLAGS_DATA_OUT;
    cbw.lun = 0;
    cbw.cb_length = cb_len;
    memcpy(cbw.cb, cb, cb_len);

    // 发送 CBW
    int ret = msc_send_cbw(msc, &cbw);
    if (ret != 0) {
        printk("MSC: CBW send failed\n");
        return ret;
    }

    // 数据阶段（如果有）
    if (data_len > 0 && data) {
        uint8_t ep = data_in ? msc->bulk_in_ep : msc->bulk_out_ep;

        ret = usb_bulk_transfer(msc->usb_device, ep, (uint8_t *)data, data_len,
                                NULL, NULL);

        if (ret < 0) {
            printk("MSC: Data transfer failed\n");
            // 继续接收 CSW
        }
    }

    // 接收 CSW
    ret = msc_receive_csw(msc, &csw);

    // 验证 tag
    if (csw.tag != cbw.tag) {
        printk("MSC: CSW tag mismatch (expected 0x%08x, got 0x%08x)\n", cbw.tag,
               csw.tag);
        return -1;
    }

    if (ret != CSW_STATUS_GOOD) {
        printk("MSC: Command failed with status %d\n", ret);
        return -1;
    }

    return 0;
}

// Bulk-Only Mass Storage Reset
int msc_bulk_only_reset(usb_msc_device_t *msc) {
    printk("MSC: Performing Bulk-Only Reset\n");

    usb_device_request_t setup = {
        .bmRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
        .bRequest = MSC_REQ_BULK_ONLY_RESET,
        .wValue = 0,
        .wIndex = msc->interface_number,
        .wLength = 0};

    return usb_control_transfer(msc->usb_device, &setup, NULL, 0, NULL, NULL);
}

// Get Max LUN
int msc_get_max_lun(usb_msc_device_t *msc, uint8_t *max_lun) {
    printk("MSC: Getting Max LUN\n");

    uint8_t lun = 0;

    usb_device_request_t setup = {.bmRequestType = USB_DIR_IN | USB_TYPE_CLASS |
                                                   USB_RECIP_INTERFACE,
                                  .bRequest = MSC_REQ_GET_MAX_LUN,
                                  .wValue = 0,
                                  .wIndex = msc->interface_number,
                                  .wLength = 1};

    int ret =
        usb_control_transfer(msc->usb_device, &setup, &lun, 1, NULL, NULL);

    if (ret == 0) {
        *max_lun = lun;
        printk("MSC: Max LUN = %d\n", lun);
    } else {
        // 如果失败，假设只有 LUN 0
        *max_lun = 0;
        printk("MSC: Get Max LUN failed, assuming 0\n");
    }

    return 0;
}

// SCSI Inquiry
int msc_inquiry(usb_msc_device_t *msc) {
    printk("\nMSC: SCSI Inquiry\n");

    uint8_t cb[16] = {0};
    cb[0] = SCSI_INQUIRY;
    cb[4] = 36; // Allocation length

    scsi_inquiry_data_t inquiry;
    memset(&inquiry, 0, sizeof(inquiry));

    int ret = msc_transfer(msc, cb, 6, &inquiry, 36, true);

    if (ret == 0) {
        printk("MSC: Inquiry successful\n");
        printk("  Peripheral Type: 0x%02x\n", inquiry.peripheral & 0x1F);
        printk("  Removable: %s\n", (inquiry.removable & 0x80) ? "Yes" : "No");

        // 保存设备信息
        memcpy(msc->vendor, inquiry.vendor_id, 8);
        msc->vendor[8] = '\0';
        memcpy(msc->product, inquiry.product_id, 16);
        msc->product[16] = '\0';
        memcpy(msc->revision, inquiry.revision, 4);
        msc->revision[4] = '\0';

        // 去除尾部空格
        for (int i = 7; i >= 0 && msc->vendor[i] == ' '; i--)
            msc->vendor[i] = '\0';
        for (int i = 15; i >= 0 && msc->product[i] == ' '; i--)
            msc->product[i] = '\0';
        for (int i = 3; i >= 0 && msc->revision[i] == ' '; i--)
            msc->revision[i] = '\0';

        printk("  Vendor: '%s'\n", msc->vendor);
        printk("  Product: '%s'\n", msc->product);
        printk("  Revision: '%s'\n", msc->revision);
    }

    return ret;
}

// SCSI Test Unit Ready
int msc_test_unit_ready(usb_msc_device_t *msc) {
    printk("MSC: Test Unit Ready\n");

    uint8_t cb[16] = {0};
    cb[0] = SCSI_TEST_UNIT_READY;

    int ret = msc_transfer(msc, cb, 6, NULL, 0, true);

    if (ret == 0) {
        printk("MSC: Unit is ready\n");
        msc->ready = true;
    } else {
        printk("MSC: Unit is not ready\n");
        msc->ready = false;
    }

    return ret;
}

// SCSI Request Sense
int msc_request_sense(usb_msc_device_t *msc, scsi_sense_data_t *sense) {
    printk("MSC: Request Sense\n");

    uint8_t cb[16] = {0};
    cb[0] = SCSI_REQUEST_SENSE;
    cb[4] = 18; // Allocation length

    memset(sense, 0, sizeof(scsi_sense_data_t));

    int ret = msc_transfer(msc, cb, 6, sense, 18, true);

    if (ret == 0) {
        printk("MSC: Sense Key: 0x%02x, ASC: 0x%02x, ASCQ: 0x%02x\n",
               sense->sense_key & 0x0F, sense->asc, sense->ascq);
    }

    return ret;
}

// SCSI Read Capacity
int msc_read_capacity(usb_msc_device_t *msc) {
    printk("\nMSC: Read Capacity\n");

    uint8_t cb[16] = {0};
    cb[0] = SCSI_READ_CAPACITY_10;

    scsi_read_capacity_data_t capacity;
    memset(&capacity, 0, sizeof(capacity));

    int ret = msc_transfer(msc, cb, 10, &capacity, 8, true);

    if (ret == 0) {
        msc->block_count = be32_to_cpu(capacity.last_lba) + 1;
        msc->block_size = be32_to_cpu(capacity.block_size);
        msc->capacity = (uint64_t)msc->block_count * msc->block_size;

        printk("MSC: Capacity information:\n");
        printk("  Last LBA: %u\n", msc->block_count - 1);
        printk("  Block Count: %u\n", msc->block_count);
        printk("  Block Size: %u bytes\n", msc->block_size);
        printk("  Total Capacity: %llu bytes (%d MB)\n", msc->capacity,
               msc->capacity / (1024 * 1024));
    }

    return ret;
}

// 读取块
int msc_read_blocks(usb_msc_device_t *msc, uint32_t lba, uint32_t count,
                    void *buffer) {
    if (!msc || !buffer || count == 0) {
        return -1;
    }

    if (lba + count > msc->block_count) {
        printk("MSC: Read beyond device capacity\n");
        return -1;
    }

    spin_lock(&msc_transfer_lock);

    // printk("MSC: Reading %u blocks from LBA %u\n", count, lba);

    uint8_t cb[16] = {0};
    cb[0] = SCSI_READ_10;
    cb[2] = (lba >> 24) & 0xFF;
    cb[3] = (lba >> 16) & 0xFF;
    cb[4] = (lba >> 8) & 0xFF;
    cb[5] = lba & 0xFF;
    cb[7] = (count >> 8) & 0xFF;
    cb[8] = count & 0xFF;

    uint32_t transfer_size = count * msc->block_size;

    int ret = msc_transfer(msc, cb, 10, buffer, transfer_size, true);

    if (ret == 0) {
        // printk("MSC: Read successful (%u bytes)\n", transfer_size);
    } else {
        printk("MSC: Read failed\n");
    }

    spin_unlock(&msc_transfer_lock);

    return ret;
}

// 写入块
int msc_write_blocks(usb_msc_device_t *msc, uint32_t lba, uint32_t count,
                     const void *buffer) {
    if (!msc || !buffer || count == 0) {
        return -1;
    }

    if (msc->write_protected) {
        printk("MSC: Device is write protected\n");
        return -1;
    }

    if (lba + count > msc->block_count) {
        printk("MSC: Write beyond device capacity\n");
        return -1;
    }

    // printk("MSC: Writing %u blocks to LBA %u\n", count, lba);

    spin_lock(&msc_transfer_lock);

    uint8_t cb[16] = {0};
    cb[0] = SCSI_WRITE_10;
    cb[2] = (lba >> 24) & 0xFF;
    cb[3] = (lba >> 16) & 0xFF;
    cb[4] = (lba >> 8) & 0xFF;
    cb[5] = lba & 0xFF;
    cb[7] = (count >> 8) & 0xFF;
    cb[8] = count & 0xFF;

    uint32_t transfer_size = count * msc->block_size;

    int ret = msc_transfer(msc, cb, 10, (void *)buffer, transfer_size, false);

    if (ret == 0) {
        // printk("MSC: Write successful (%u bytes)\n", transfer_size);
    } else {
        printk("MSC: Write failed\n");
    }

    spin_unlock(&msc_transfer_lock);

    return ret;
}

uint64_t msc_read(void *data, uint64_t lba, void *buffer, uint64_t size) {
    return msc_read_blocks(data, lba, size, buffer) == 0 ? size : -EIO;
}

uint64_t msc_write(void *data, uint64_t lba, void *buffer, uint64_t size) {
    return msc_write_blocks(data, lba, size, buffer) == 0 ? size : -EIO;
}

// 探测 MSC 设备
int usb_msc_probe(usb_device_t *device) {
    if (!device) {
        return -1;
    }

    // 检查设备类
    if (device->descriptor.bDeviceClass != USB_CLASS_MASS_STORAGE &&
        device->descriptor.bDeviceClass != 0x00) {
        printk("MSC: Not a mass storage device (class=0x%02x)\n",
               device->descriptor.bDeviceClass);
        return -1;
    }

    // 解析配置描述符，查找 MSC 接口
    if (!device->config_descriptor) {
        printk("MSC: No configuration descriptor\n");
        return -1;
    }

    uint8_t *ptr = (uint8_t *)device->config_descriptor;
    uint8_t *end = ptr + device->config_descriptor->wTotalLength;
    ptr += sizeof(usb_config_descriptor_t);

    usb_interface_descriptor_t *msc_iface = NULL;
    usb_endpoint_descriptor_t *bulk_in = NULL;
    usb_endpoint_descriptor_t *bulk_out = NULL;

    while (ptr < end) {
        uint8_t len = ptr[0];
        uint8_t type = ptr[1];

        if (len == 0)
            break;
        if (ptr + len > end)
            break;

        if (type == USB_DT_INTERFACE) {
            usb_interface_descriptor_t *iface =
                (usb_interface_descriptor_t *)ptr;
            if (iface->bInterfaceClass == USB_CLASS_MASS_STORAGE &&
                iface->bInterfaceProtocol == MSC_PROTOCOL_BBB) {
                msc_iface = iface;
                printk("MSC: Found MSC interface %d\n",
                       iface->bInterfaceNumber);
                printk("  Subclass: 0x%02x\n", iface->bInterfaceSubClass);
                printk("  Protocol: 0x%02x (Bulk-Only)\n",
                       iface->bInterfaceProtocol);
            }
        } else if (type == USB_DT_ENDPOINT && msc_iface) {
            usb_endpoint_descriptor_t *ep = (usb_endpoint_descriptor_t *)ptr;

            if ((ep->bmAttributes & 0x03) == USB_ENDPOINT_XFER_BULK) {
                if (ep->bEndpointAddress & 0x80) {
                    bulk_in = ep;
                    printk("  Bulk IN: 0x%02x, MaxPacket=%d\n",
                           ep->bEndpointAddress, ep->wMaxPacketSize);
                } else {
                    bulk_out = ep;
                    printk("  Bulk OUT: 0x%02x, MaxPacket=%d\n",
                           ep->bEndpointAddress, ep->wMaxPacketSize);
                }
            }
        }

        ptr += len;
    }

    if (!msc_iface || !bulk_in || !bulk_out) {
        printk("MSC: Required endpoints not found\n");
        return -1;
    }

    // 创建 MSC 设备结构
    usb_msc_device_t *msc =
        (usb_msc_device_t *)malloc(sizeof(usb_msc_device_t));
    if (!msc) {
        printk("MSC: Failed to allocate device structure\n");
        return -1;
    }

    memset(msc, 0, sizeof(usb_msc_device_t));
    msc->usb_device = device;
    msc->interface_number = msc_iface->bInterfaceNumber;
    msc->bulk_in_ep = bulk_in->bEndpointAddress;
    msc->bulk_out_ep = bulk_out->bEndpointAddress;
    msc->max_packet_size = bulk_in->wMaxPacketSize;

    // 获取 Max LUN
    msc_get_max_lun(msc, &msc->max_lun);

    // 执行初始化命令
    printk("\nMSC: Initializing device...\n");

    // Test Unit Ready（可能失败，正常）
    msc_test_unit_ready(msc);

    // Inquiry
    if (msc_inquiry(msc) != 0) {
        printk("MSC: Inquiry failed\n");
        free(msc);
        return -1;
    }

    // 等待设备就绪
    int retries = 5;
    while (retries-- > 0) {
        if (msc_test_unit_ready(msc) == 0) {
            break;
        }
    }

    // Read Capacity
    if (msc_read_capacity(msc) != 0) {
        printk("MSC: Read Capacity failed\n");
        free(msc);
        return -1;
    }

    // 添加到设备列表
    msc->next = msc_devices;
    msc_devices = msc;

    printk("Vendor: %s\n", msc->vendor);
    printk("Product: %s\n", msc->product);
    printk("Capacity: %d MB\n", msc->capacity / (1024 * 1024));
    printk("Block Size: %u bytes\n", msc->block_size);

    // regist_blkdev("msc", msc, (uint64_t)msc->block_size,
    //               (uint64_t)msc->block_size * (uint64_t)msc->block_count,
    //               DEFAULT_PAGE_SIZE * 4, msc_read, msc_write);

    // set_have_usb_storage(true);

    return 0;
}

// 移除 MSC 设备
void usb_msc_remove(usb_msc_device_t *msc) {
    if (!msc)
        return;

    printk("MSC: Removing device\n");

    // 从列表中移除
    usb_msc_device_t **prev = &msc_devices;
    while (*prev) {
        if (*prev == msc) {
            *prev = msc->next;
            break;
        }
        prev = &(*prev)->next;
    }

    free(msc);
}

int msc_probe(usb_device_t *usbdev) { return usb_msc_probe(usbdev); }

int msc_remove(usb_device_t *usbdev) {
    usb_msc_remove((usb_msc_device_t *)usbdev->private_data);
    return 0;
}

usb_driver_t msc_driver = {
    .class = USB_CLASS_MASS_STORAGE,
    .subclass = 0x00,
    .probe = msc_probe,
    .remove = msc_remove,
};

__attribute__((visibility("default"))) int dlmain() {
    register_usb_driver(&msc_driver);

    return 0;
}
