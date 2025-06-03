#pragma once

#include <libs/klibc.h>
#include <drivers/usb/usb.h>

// SCSI命令定义
enum
{
    SCSI_INQUIRY = 0x12,
    SCSI_READ_CAPACITY = 0x25,
    SCSI_READ_10 = 0x28,
    SCSI_WRITE_10 = 0x2A,
};

// CBW/CSW结构体
typedef struct
{
    uint32_t dCBWSignature;
    uint32_t dCBWTag;
    uint32_t dCBWDataTransferLength;
    uint8_t bmCBWFlags;
    uint8_t bCBWLUN;
    uint8_t bCBWCBLength;
    uint8_t CBWCB[16];
} __attribute__((packed)) usb_msc_cbw_t;

typedef struct
{
    uint32_t dCSWSignature;
    uint32_t dCSWTag;
    uint32_t dCSWDataResidue;
    uint8_t bCSWStatus;
} __attribute__((packed)) usb_msc_csw_t;

struct usbdevice_s;

typedef struct
{
    struct usbdevice_s *udev;
    struct usb_pipe *bulk_in;
    struct usb_pipe *bulk_out;
    uint32_t block_size;
    uint64_t block_count;
} usb_msc_device;

int usb_msc_setup(struct usbdevice_s *usbdev);
