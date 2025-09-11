#include <libs/aether/block.h>
#include <libs/aether/stdio.h>
#include "msc.h"
#include "usb.h"

spinlock_t usb_bulk_transfer_lock = {0};

int usb_bulk_transfer(struct usb_pipe *pipe, void *data, size_t len, bool is_read)
{
    if (!pipe || !pipe->cntl)
        return -EINVAL;

    spin_lock(&usb_bulk_transfer_lock);

    int ret = (usb_send_bulk(pipe, is_read ? USB_DIR_IN : USB_DIR_OUT, data, len) == 0) ? len : -EIO;

    spin_unlock(&usb_bulk_transfer_lock);

    return ret;
}

spinlock_t usb_msc_transfer_lock = {0};

static int usb_msc_transfer(usb_msc_device *dev, void *cmd, uint8_t cmd_length, void *data, size_t data_len, bool is_read)
{
    spin_lock(&usb_msc_transfer_lock);

    // 发送CBW
    usb_msc_cbw_t cbw;
    memset(&cbw, 0, sizeof(usb_msc_cbw_t));
    cbw.dCBWSignature = 0x43425355;
    cbw.dCBWTag = 1;
    cbw.dCBWDataTransferLength = data_len;
    cbw.bmCBWFlags = is_read ? USB_DIR_IN : USB_DIR_OUT;
    cbw.bCBWLUN = 0;
    cbw.bCBWCBLength = cmd_length;

    memcpy(cbw.CBWCB, cmd, cmd_length);

    if (usb_bulk_transfer(dev->bulk_out, &cbw, sizeof(cbw), false) < 0)
    {
        spin_unlock(&usb_msc_transfer_lock);
        printk("Failed to transfer cbw!!!\n");
        return -1;
    }

    // 数据传输
    if (data_len > 0)
    {
        struct usb_pipe *pipe = is_read ? dev->bulk_in : dev->bulk_out;
        if (usb_bulk_transfer(pipe, data, data_len, is_read) < 0)
        {
            spin_unlock(&usb_msc_transfer_lock);
            printk("Failed to transfer data!!!\n");
            return -1;
        }
    }

    // 接收CSW
    usb_msc_csw_t csw;
    if (usb_bulk_transfer(dev->bulk_in, &csw, sizeof(csw), true) < 0)
    {
        spin_unlock(&usb_msc_transfer_lock);
        printk("Failed to transfer csw!!!\n");
        return -1;
    }

    if (csw.bCSWStatus == 0)
    {
        spin_unlock(&usb_msc_transfer_lock);
        return 0;
    }

    printk("Failed to transfer!!! csw.bCSWStatus = %d\n", csw.bCSWStatus);

    spin_unlock(&usb_msc_transfer_lock);
    return -1;
}

// SCSI 10命令格式
static int usb_msc_read_10(usb_msc_device *dev, uint64_t lba, void *buf, uint64_t count)
{
    uint8_t cmd[16] = {
        SCSI_READ_10,
        0,
        (lba >> 24) & 0xFF,
        (lba >> 16) & 0xFF,
        (lba >> 8) & 0xFF,
        lba & 0xFF,
        0,
        (count >> 8) & 0xFF,
        count & 0xFF,
        0};

    return usb_msc_transfer(dev, cmd, 10, buf, count * dev->block_size, true) == 0 ? count : 0;
}

static int usb_msc_write_10(usb_msc_device *dev, uint64_t lba, void *buf, uint64_t count)
{
    uint8_t cmd[16] = {
        SCSI_WRITE_10,
        0,
        (lba >> 24) & 0xFF,
        (lba >> 16) & 0xFF,
        (lba >> 8) & 0xFF,
        lba & 0xFF,
        0,
        (count >> 8) & 0xFF,
        count & 0xFF,
        0};

    return usb_msc_transfer(dev, cmd, 10, buf, count * dev->block_size, false) == 0 ? count : 0;
}

// SCSI 12命令格式
static int usb_msc_read_12(usb_msc_device *dev, uint64_t lba, void *buf, uint64_t count)
{
    uint8_t cmd[16] = {
        SCSI_READ_12,
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

    return usb_msc_transfer(dev, cmd, 12, buf, count * dev->block_size, true) == 0 ? count : 0;
}

static int usb_msc_write_12(usb_msc_device *dev, uint64_t lba, void *buf, uint64_t count)
{
    uint8_t cmd[16] = {
        SCSI_WRITE_12,
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

    return usb_msc_transfer(dev, cmd, 12, buf, count * dev->block_size, false) == 0 ? count : 0;
}

// SCSI 16命令格式
static int usb_msc_read_16(usb_msc_device *dev, uint64_t lba, void *buf, uint64_t count)
{
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

    return usb_msc_transfer(dev, cmd, 16, buf, count * dev->block_size, true) == 0 ? count : 0;
}

static int usb_msc_write_16(usb_msc_device *dev, uint64_t lba, void *buf, uint64_t count)
{
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

    return usb_msc_transfer(dev, cmd, 16, buf, count * dev->block_size, false) == 0 ? count : 0;
}

// INQUIRY命令响应数据结构
typedef struct {
    uint8_t peripheral_device_type;
    uint8_t removable;
    uint8_t version;
    uint8_t response_data_format;
    uint8_t additional_length;
    uint8_t reserved[3];
    uint8_t vendor_identification[8];
    uint8_t product_identification[16];
    uint8_t product_revision_level[4];
} __attribute__((packed)) scsi_inquiry_data_t;

// VPD页面支持数据结构
typedef struct {
    uint8_t peripheral_device_type;
    uint8_t page_code;
    uint16_t page_length;
    uint8_t supported_vpd_pages[256];
} __attribute__((packed)) scsi_vpd_supported_pages_t;

typedef struct {
    uint8_t peripheral_device_type;
    uint8_t page_code;
    uint16_t page_length;
    uint8_t longest_transfer_length[4];
    uint8_t max_transfer_length[4];
    uint8_t optimal_transfer_length[4];
    uint8_t max_prefetch_length[4];
    uint8_t max_unmap_lba_count[4];
    uint8_t max_unmap_block_descriptors[4];
    uint8_t optimal_unmap_granularity[4];
    uint8_t unmap_granularity_alignment[4];
    uint8_t max_write_same_length[8];
    uint8_t capabilities;
} __attribute__((packed)) scsi_vpd_block_limits_t;

static int usb_msc_fallback_detection(usb_msc_device *dev);

// 检测设备支持的SCSI命令集
static int usb_msc_detect_scsi_capability(usb_msc_device *dev)
{
    // 默认使用SCSI 10
    dev->read_func = usb_msc_read_10;
    dev->write_func = usb_msc_write_10;
    dev->scsi_version = SCSI_VERSION_10;

    // 发送INQUIRY命令获取设备信息
    scsi_inquiry_data_t inquiry_data;
    uint8_t inquiry_cmd[16] = {SCSI_INQUIRY, 0, 0, 0, 0x24, 0}; // 限制为36字节，避免超过255

    if (usb_msc_transfer(dev, inquiry_cmd, 6, &inquiry_data, sizeof(inquiry_data), true) != 0)
    {
        printk("[USB MSC]: INQUIRY command failed, using fallback detection\n");

        // INQUIRY失败，使用后备检测方法
        return usb_msc_fallback_detection(dev);
    }

    printk("[USB MSC]: Starting SCSI capability detection\n");
    printk("[USB MSC]: Device Vendor: %.8s, Product: %.16s, Revision: %.4s\n",
           inquiry_data.vendor_identification, inquiry_data.product_identification, inquiry_data.product_revision_level);

    // 检查SCSI版本支持
    uint8_t scsi_version = inquiry_data.version;

    printk("[USB MSC]: SCSI Version: 0x%02X (", scsi_version);
    switch (scsi_version) {
        case 0x00: printk("SCSI-1/SPC"); break;
        case 0x01: printk("SCSI-2/SPC-1"); break;
        case 0x02: printk("SCSI-3/SPC-2"); break;
        case 0x03: printk("SPC-3"); break;
        case 0x04: printk("SPC-4"); break;
        case 0x05: printk("SPC-5"); break;
        case 0x06: printk("SPC-6"); break;
        default: printk("Unknown"); break;
    }
    printk(")\n");

    // 查询支持的VPD页面以获取更详细的能力信息
    scsi_vpd_supported_pages_t vpd_pages;
    uint8_t vpd_cmd[16] = {SCSI_INQUIRY, 1, 0x00, 0, 0xFF, 0}; // 最大255字节

    bool has_block_limits = false;
    bool has_16byte_cdb = false;

    if (usb_msc_transfer(dev, vpd_cmd, 6, &vpd_pages, sizeof(vpd_pages), true) == 0)
    {
        for (int i = 0; i < vpd_pages.page_length; i++)
        {
            if (vpd_pages.supported_vpd_pages[i] == 0xB0)
            {
                has_block_limits = true;
            }
        }

        // 检查是否支持16字节CDB
        scsi_vpd_block_limits_t block_limits;
        if (has_block_limits)
        {
            uint8_t block_limits_cmd[16] = {SCSI_INQUIRY, 1, 0xB0, 0, 0x3C, 0}; // Block Limits VPD页面通常60字节
            if (usb_msc_transfer(dev, block_limits_cmd, 6, &block_limits, sizeof(block_limits), true) == 0)
            {
                // 检查Capabilities字段中的16字节CDB支持位
                if (block_limits.capabilities & 0x01)
                {
                    has_16byte_cdb = true;
                    printk("[USB MSC]: Device explicitly supports 16-byte CDB (capability bit set)\n");
                }
                else
                {
                    printk("[USB MSC]: Device does not explicitly support 16-byte CDB (capability bit not set)\n");
                }
            }
        }
    }

    // 根据设备能力选择最优命令集
    if (has_16byte_cdb && scsi_version >= 0x04)
    {
        // 设备明确支持16字节CDB且SCSI版本足够
        printk("[USB MSC]: Using SCSI 16 (explicit 16-byte CDB support detected)\n");
        dev->read_func = usb_msc_read_16;
        dev->write_func = usb_msc_write_16;
        dev->scsi_version = SCSI_VERSION_16;
    }
    else if (scsi_version >= 0x05)
    {
        // SPC-4或更高版本，支持SCSI 16
        printk("[USB MSC]: Using SCSI 16 (SPC-4 or later specification)\n");
        dev->read_func = usb_msc_read_16;
        dev->write_func = usb_msc_write_16;
        dev->scsi_version = SCSI_VERSION_16;
    }
    else if (scsi_version >= 0x03)
    {
        // SPC-2或SPC-3，支持SCSI 12
        printk("[USB MSC]: Using SCSI 12 (SPC-2/SPC-3 specification)\n");
        dev->read_func = usb_msc_read_12;
        dev->write_func = usb_msc_write_12;
        dev->scsi_version = SCSI_VERSION_12;
    }
    else
    {
        // SPC/SPC-1或更低，使用SCSI 10
        printk("[USB MSC]: Using SCSI 10 (legacy SCSI specification)\n");
        dev->read_func = usb_msc_read_10;
        dev->write_func = usb_msc_write_10;
        dev->scsi_version = SCSI_VERSION_10;
    }

    return 0;
}

// 后备检测方法（当INQUIRY命令失败时使用）
static int usb_msc_fallback_detection(usb_msc_device *dev)
{
    printk("[USB MSC]: INQUIRY command failed, using fallback detection method\n");

    // 尝试使用SCSI 16容量查询来检测支持
    uint8_t capacity_16[16];
    uint8_t cmd_16[16] = {SCSI_READ_CAPACITY_16, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    if (usb_msc_transfer(dev, cmd_16, 16, capacity_16, sizeof(capacity_16), true) == 0)
    {
        // SCSI 16容量查询成功，使用SCSI 16
        printk("[USB MSC]: Fallback detection: SCSI 16 READ CAPACITY(16) command succeeded\n");
        dev->read_func = usb_msc_read_16;
        dev->write_func = usb_msc_write_16;
        dev->scsi_version = SCSI_VERSION_16;
        return 0;
    }

    // 尝试SCSI 12读写命令
    uint8_t test_buffer[512];
    uint8_t test_cmd[16] = {SCSI_READ_12, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};

    if (usb_msc_transfer(dev, test_cmd, 12, test_buffer, 512, true) == 0)
    {
        // SCSI 12命令成功，使用SCSI 12
        printk("[USB MSC]: Fallback detection: SCSI 12 READ(12) command succeeded\n");
        dev->read_func = usb_msc_read_12;
        dev->write_func = usb_msc_write_12;
        dev->scsi_version = SCSI_VERSION_12;
        return 0;
    }

    // 使用默认的SCSI 10
    printk("[USB MSC]: Fallback detection: No advanced SCSI commands supported, using SCSI 10\n");
    dev->read_func = usb_msc_read_10;
    dev->write_func = usb_msc_write_10;
    dev->scsi_version = SCSI_VERSION_10;

    return 0;
}

uint64_t usb_msc_read_blocks(void *dev, uint64_t lba, void *buf, uint64_t count)
{
    usb_msc_device *msc_dev = (usb_msc_device *)dev;
    return msc_dev->read_func(msc_dev, lba, buf, count);
}

uint64_t usb_msc_write_blocks(void *dev, uint64_t lba, void *buf, uint64_t count)
{
    usb_msc_device *msc_dev = (usb_msc_device *)dev;
    return msc_dev->write_func(msc_dev, lba, buf, count);
}

int usb_msc_setup(struct usbdevice_s *usbdev)
{
    usb_msc_device *dev = malloc(sizeof(usb_msc_device));
    if (!dev)
        return -ENOMEM;

    memset(dev, 0, sizeof(usb_msc_device));
    dev->udev = usbdev;

    usbdev->desc = dev;

    struct usb_pipe *inpipe = NULL, *outpipe = NULL;
    struct usb_endpoint_descriptor *indesc = usb_find_desc(
        usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_IN);
    struct usb_endpoint_descriptor *outdesc = usb_find_desc(
        usbdev, USB_ENDPOINT_XFER_BULK, USB_DIR_OUT);

    if (!indesc || !outdesc)
        goto fail;

    inpipe = usb_alloc_pipe(usbdev, indesc);
    outpipe = usb_alloc_pipe(usbdev, outdesc);

    if (!inpipe || !outpipe)
        goto fail;

    dev->bulk_in = inpipe;
    dev->bulk_out = outpipe;

    uint8_t capacity[8];
    uint8_t cmd[16] = {SCSI_READ_CAPACITY_10};
    if (usb_msc_transfer(dev, cmd, 10, capacity, sizeof(capacity), true) == 0)
    {
        dev->block_count = be32toh(*(uint32_t *)capacity) + 1;
        dev->block_size = be32toh(*(uint32_t *)(capacity + 4));
    }
    else
    {
        dev->block_size = 512;
        dev->block_count = UINT64_MAX / 512;
    }

    usb_msc_detect_scsi_capability(dev);

    regist_blkdev("MSC", dev, dev->block_size, dev->block_count * dev->block_size, DEFAULT_PAGE_SIZE, usb_msc_read_blocks, usb_msc_write_blocks);

    return 0;

fail:
    printk("Failed initialize mass storage device!!!\n");

    usb_free_pipe(usbdev, inpipe);
    usb_free_pipe(usbdev, outpipe);
    free(dev);
    return -1;
}
