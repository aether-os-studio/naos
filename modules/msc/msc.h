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
struct usb_msc_lun;

struct usb_msc_device;
typedef struct usb_msc_device usb_msc_device;
typedef struct usb_msc_lun usb_msc_lun;

// 函数指针类型定义
typedef uint64_t (*usb_msc_read_func_t)(usb_msc_lun *lun, uint64_t lba,
                                        void *buf, uint64_t count);
typedef uint64_t (*usb_msc_write_func_t)(usb_msc_lun *lun, uint64_t lba,
                                         void *buf, uint64_t count);

struct usb_msc_lun {
    usb_msc_device *ctrl;
    uint8_t lun;
    uint32_t block_size;
    uint64_t block_count;
    bool registered;
};

struct usb_msc_device {
    struct usbdevice_s *udev;
    struct usbdevice_a_interface *iface;
    struct usb_pipe *bulk_in;
    struct usb_pipe *bulk_out;
    spinlock_t lock;
    uint32_t next_tag;
    uint8_t lun_count;
    usb_msc_lun *luns;
};

uint64_t usb_msc_read_blocks(void *dev, uint64_t lba, void *buf,
                             uint64_t count);
uint64_t usb_msc_write_blocks(void *dev, uint64_t lba, void *buf,
                              uint64_t count);
