#include "msc.h"

int usb_bulk_transfer(struct usb_pipe *pipe, void *data, size_t len, bool is_read)
{
    if (!pipe || !pipe->cntl)
        return -EINVAL;

    switch (pipe->cntl->type)
    {
    case USB_TYPE_XHCI:
        return (usb_send_bulk(pipe, is_read ? USB_DIR_IN : USB_DIR_OUT, data, len) == 0) ? len : -EIO;
    default:
        return -EOPNOTSUPP;
    }
}

static int usb_msc_transfer(usb_msc_device *dev, void *cmd, void *data, size_t data_len, bool is_read)
{
    // 发送CBW
    usb_msc_cbw_t cbw;
    memset(&cbw, 0, sizeof(usb_msc_cbw_t));
    cbw.dCBWSignature = 0x43425355;
    cbw.dCBWTag = 1;
    cbw.dCBWDataTransferLength = data_len;
    cbw.bmCBWFlags = is_read ? USB_DIR_IN : USB_DIR_OUT;
    cbw.bCBWLUN = 0;
    cbw.bCBWCBLength = 16;

    memcpy(cbw.CBWCB, cmd, 16);

    if (usb_bulk_transfer(dev->bulk_out, &cbw, sizeof(cbw), false) < 0)
        return -1;

    // 数据传输
    if (data_len > 0)
    {
        struct usb_pipe *pipe = is_read ? dev->bulk_in : dev->bulk_out;
        if (usb_bulk_transfer(pipe, data, data_len, is_read) < 0)
            return -1;
    }

    // 接收CSW
    usb_msc_csw_t csw;
    if (usb_bulk_transfer(dev->bulk_in, &csw, sizeof(csw), true) < 0)
        return -1;

    return (csw.bCSWStatus == 0) ? 0 : -1;
}

uint64_t usb_msc_read_blocks(void *dev, uint64_t lba, void *buf, uint64_t count)
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

    return usb_msc_transfer(dev, cmd, buf, count * (((usb_msc_device *)dev)->block_size ? ((usb_msc_device *)dev)->block_size : 512), true) == 0 ? count : 0;
}

uint64_t usb_msc_write_blocks(void *dev, uint64_t lba, void *buf, uint64_t count)
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

    return usb_msc_transfer(dev, cmd, buf, count * (((usb_msc_device *)dev)->block_size ? ((usb_msc_device *)dev)->block_size : 512), false) == 0 ? count : 0;
}

int usb_msc_setup(struct usbdevice_s *usbdev)
{
    usb_msc_device *dev = malloc(sizeof(usb_msc_device));
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
    uint8_t cmd[16] = {SCSI_READ_CAPACITY};
    if (usb_msc_transfer(dev, cmd, capacity, sizeof(capacity), true) == 0)
    {
        dev->block_count = be32toh(*(uint32_t *)capacity) + 1;
        dev->block_size = be32toh(*(uint32_t *)(capacity + 4));
    }

    regist_blkdev("usb msc", dev, dev->block_size, dev->block_count * dev->block_size, MIN(inpipe->maxpacket, outpipe->maxpacket), usb_msc_read_blocks, usb_msc_write_blocks);

    return 0;
fail:
    usb_free_pipe(usbdev, inpipe);
    usb_free_pipe(usbdev, outpipe);
    return -1;
};
