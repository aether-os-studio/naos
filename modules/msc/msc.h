#pragma once

#include <libs/aether/block.h>
#include <libs/aether/usb.h>

// CBW/CSW结构体
typedef struct {
    uint32_t dCBWSignature;
    uint32_t dCBWTag;
    uint32_t dCBWDataTransferLength;
    uint8_t bmCBWFlags;
    uint8_t bCBWLUN;
    uint8_t bCBWCBLength;
    uint8_t CBWCB[16];
} __attribute__((packed)) usb_msc_cbw_t;

typedef struct {
    uint32_t dCSWSignature;
    uint32_t dCSWTag;
    uint32_t dCSWDataResidue;
    uint8_t bCSWStatus;
} __attribute__((packed)) usb_msc_csw_t;

struct usbdevice_s;

struct usb_msc_device;
typedef struct usb_msc_device usb_msc_device;

// 函数指针类型定义
typedef uint64_t (*usb_msc_read_func_t)(usb_msc_device *dev, uint64_t lba,
                                        void *buf, uint64_t count);
typedef uint64_t (*usb_msc_write_func_t)(usb_msc_device *dev, uint64_t lba,
                                         void *buf, uint64_t count);

struct usb_msc_device {
    struct usbdevice_s *udev;
    uint8_t lun;
    struct usb_pipe *bulk_in;
    struct usb_pipe *bulk_out;
    uint32_t block_size;
    uint64_t block_count;
    enum scsi_version scsi_version;
    usb_msc_read_func_t read_func;
    usb_msc_write_func_t write_func;
};

int usb_msc_setup(struct usbdevice_s *usbdev);
uint64_t usb_msc_read_blocks(void *dev, uint64_t lba, void *buf,
                             uint64_t count);
uint64_t usb_msc_write_blocks(void *dev, uint64_t lba, void *buf,
                              uint64_t count);
