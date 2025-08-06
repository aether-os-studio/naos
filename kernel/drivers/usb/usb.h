// USB functions and data.
#ifndef __USB_H
#define __USB_H

#include <libs/klibc.h>
#include "xhci-hcd.h"

// Information on a USB end point.
struct usb_pipe
{
    union
    {
        struct usb_s *cntl;
        struct usb_pipe *freenext;
    };
    uint8_t type;
    uint8_t ep;
    uint8_t devaddr;
    uint8_t speed;
    uint16_t maxpacket;
    uint8_t eptype;
};

// Common information for usb devices.
struct usbdevice_s
{
    struct usbhub_s *hub;
    struct usb_pipe *defpipe;
    uint32_t port;
    struct usb_config_descriptor *config;
    struct usb_interface_descriptor *iface;
    int imax;
    uint8_t speed;
    uint8_t devaddr;
};

// Common information for usb controllers.
struct usb_s
{
    struct usb_pipe *freelist;
    spinlock_t resetlock;
    void *mmio;
    uint8_t type;
    uint8_t maxaddr;
};

// Information for enumerating USB hubs
struct usbhub_s
{
    struct usbhub_op_s *op;
    struct usbdevice_s *usbdev;
    struct usb_s *cntl;
    spinlock_t lock;
    uint32_t detectend;
    uint32_t port;
    uint32_t threads;
    uint32_t portcount;
    uint32_t devcount;
};

// Hub callback (32bit) info
struct usbhub_op_s
{
    int (*detect)(struct usbhub_s *hub, uint32_t port);
    int (*reset)(struct usbhub_s *hub, uint32_t port);
    int (*portmap)(struct usbhub_s *hub, uint32_t port);
    void (*disconnect)(struct usbhub_s *hub, uint32_t port);
};

#define USB_TYPE_UHCI 1
#define USB_TYPE_OHCI 2
#define USB_TYPE_EHCI 3
#define USB_TYPE_XHCI 4

#define USB_FULLSPEED 0
#define USB_LOWSPEED 1
#define USB_HIGHSPEED 2
#define USB_SUPERSPEED 3

#define USB_MAXADDR 127

/****************************************************************
 * usb structs and flags
 ****************************************************************/

// USB mandated timings (in ms)
#define USB_TIME_SIGATT 100
#define USB_TIME_ATTDB 100
#define USB_TIME_DRST 10
#define USB_TIME_DRSTR 50
#define USB_TIME_RSTRCY 10

#define USB_TIME_STATUS 50
#define USB_TIME_DATAIN 500
#define USB_TIME_COMMAND 5000

#define USB_TIME_SETADDR_RECOVERY 2

#define USB_PID_OUT 0xe1
#define USB_PID_IN 0x69
#define USB_PID_SETUP 0x2d

#define USB_DIR_OUT 0   /* to device */
#define USB_DIR_IN 0x80 /* to host */

#define USB_TYPE_MASK (0x03 << 5)
#define USB_TYPE_STANDARD (0x00 << 5)
#define USB_TYPE_CLASS (0x01 << 5)
#define USB_TYPE_VENDOR (0x02 << 5)
#define USB_TYPE_RESERVED (0x03 << 5)

#define USB_RECIP_MASK 0x1f
#define USB_RECIP_DEVICE 0x00
#define USB_RECIP_INTERFACE 0x01
#define USB_RECIP_ENDPOINT 0x02
#define USB_RECIP_OTHER 0x03

#define USB_REQ_GET_STATUS 0x00
#define USB_REQ_CLEAR_FEATURE 0x01
#define USB_REQ_SET_FEATURE 0x03
#define USB_REQ_SET_ADDRESS 0x05
#define USB_REQ_GET_DESCRIPTOR 0x06
#define USB_REQ_SET_DESCRIPTOR 0x07
#define USB_REQ_GET_CONFIGURATION 0x08
#define USB_REQ_SET_CONFIGURATION 0x09
#define USB_REQ_GET_INTERFACE 0x0A
#define USB_REQ_SET_INTERFACE 0x0B
#define USB_REQ_SYNCH_FRAME 0x0C

struct usb_ctrlrequest
{
    uint8_t bRequestType;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} __attribute__((packed));

#define USB_DT_DEVICE 0x01
#define USB_DT_CONFIG 0x02
#define USB_DT_STRING 0x03
#define USB_DT_INTERFACE 0x04
#define USB_DT_ENDPOINT 0x05
#define USB_DT_DEVICE_QUALIFIER 0x06
#define USB_DT_OTHER_SPEED_CONFIG 0x07
#define USB_DT_ENDPOINT_COMPANION 0x30

struct usb_device_descriptor
{
    uint8_t bLength;
    uint8_t bDescriptorType;

    uint16_t bcdUSB;
    uint8_t bDeviceClass;
    uint8_t bDeviceSubClass;
    uint8_t bDeviceProtocol;
    uint8_t bMaxPacketSize0;
    uint16_t idVendor;
    uint16_t idProduct;
    uint16_t bcdDevice;
    uint8_t iManufacturer;
    uint8_t iProduct;
    uint8_t iSerialNumber;
    uint8_t bNumConfigurations;
} __attribute__((packed));

#define USB_CLASS_PER_INTERFACE 0 /* for DeviceClass */
#define USB_CLASS_AUDIO 1
#define USB_CLASS_COMM 2
#define USB_CLASS_HID 3
#define USB_CLASS_PHYSICAL 5
#define USB_CLASS_STILL_IMAGE 6
#define USB_CLASS_PRINTER 7
#define USB_CLASS_MASS_STORAGE 8
#define USB_CLASS_HUB 9

struct usb_config_descriptor
{
    uint8_t bLength;
    uint8_t bDescriptorType;

    uint16_t wTotalLength;
    uint8_t bNumInterfaces;
    uint8_t bConfigurationValue;
    uint8_t iConfiguration;
    uint8_t bmAttributes;
    uint8_t bMaxPower;
} __attribute__((packed));

struct usb_interface_descriptor
{
    uint8_t bLength;
    uint8_t bDescriptorType;

    uint8_t bInterfaceNumber;
    uint8_t bAlternateSetting;
    uint8_t bNumEndpoints;
    uint8_t bInterfaceClass;
    uint8_t bInterfaceSubClass;
    uint8_t bInterfaceProtocol;
    uint8_t iInterface;
} __attribute__((packed));

struct usb_endpoint_descriptor
{
    uint8_t bLength;
    uint8_t bDescriptorType;

    uint8_t bEndpointAddress;
    uint8_t bmAttributes;
    uint16_t wMaxPacketSize;
    uint8_t bInterval;
} __attribute__((packed));

#define USB_ENDPOINT_NUMBER_MASK 0x0f /* in bEndpointAddress */
#define USB_ENDPOINT_DIR_MASK 0x80

#define USB_ENDPOINT_XFERTYPE_MASK 0x03 /* in bmAttributes */
#define USB_ENDPOINT_XFER_CONTROL 0
#define USB_ENDPOINT_XFER_ISOC 1
#define USB_ENDPOINT_XFER_BULK 2
#define USB_ENDPOINT_XFER_INT 3
#define USB_ENDPOINT_MAX_ADJUSTABLE 0x80

#define USB_CONTROL_SETUP_SIZE 8

/****************************************************************
 * usb mass storage flags
 ****************************************************************/

#define US_SC_ATAPI_8020 0x02
#define US_SC_ATAPI_8070 0x05
#define US_SC_SCSI 0x06

#define US_PR_BULK 0x50 /* bulk-only transport */
#define US_PR_UAS 0x62  /* usb attached scsi   */

/****************************************************************
 * function defs
 ****************************************************************/

// usb.c
int usb_send_bulk(struct usb_pipe *pipe, int dir, void *data, int datasize);
int usb_poll_intr(struct usb_pipe *pipe, void *data);
int usb_32bit_pipe(struct usb_pipe *pipe_fl);

// Allocate, update, or free a usb pipe.
static inline struct usb_pipe *usb_realloc_pipe(struct usbdevice_s *usbdev, struct usb_pipe *pipe, struct usb_endpoint_descriptor *epdesc)
{
    switch (usbdev->hub->cntl->type)
    {
    default:
    // case USB_TYPE_UHCI:
    //     return uhci_realloc_pipe(usbdev, pipe, epdesc);
    // case USB_TYPE_OHCI:
    //     return ohci_realloc_pipe(usbdev, pipe, epdesc);
    // case USB_TYPE_EHCI:
    //     return ehci_realloc_pipe(usbdev, pipe, epdesc);
    case USB_TYPE_XHCI:
        return xhci_realloc_pipe(usbdev, pipe, epdesc);
    }
}

// Allocate a usb pipe.
static inline struct usb_pipe *usb_alloc_pipe(struct usbdevice_s *usbdev, struct usb_endpoint_descriptor *epdesc)
{
    return usb_realloc_pipe(usbdev, NULL, epdesc);
}

// Free an allocated control or bulk pipe.
static inline void usb_free_pipe(struct usbdevice_s *usbdev, struct usb_pipe *pipe)
{
    if (!pipe)
        return;
    usb_realloc_pipe(usbdev, pipe, NULL);
}

int usb_send_default_control(struct usb_pipe *pipe, const struct usb_ctrlrequest *req, void *data);
int usb_is_freelist(struct usb_s *cntl, struct usb_pipe *pipe);
void usb_add_freelist(struct usb_pipe *pipe);
struct usb_pipe *usb_get_freelist(struct usb_s *cntl, uint8_t eptype);
void usb_desc2pipe(struct usb_pipe *pipe, struct usbdevice_s *usbdev, struct usb_endpoint_descriptor *epdesc);

static inline int __fls(unsigned int x)
{
    if (x == 0)
        return -1;

    int pos = 0;
    if (x & 0xFFFF0000)
    {
        pos += 16;
        x >>= 16;
    }
    if (x & 0xFF00)
    {
        pos += 8;
        x >>= 8;
    }
    if (x & 0xF0)
    {
        pos += 4;
        x >>= 4;
    }
    if (x & 0xC)
    {
        pos += 2;
        x >>= 2;
    }
    if (x & 0x2)
    {
        pos += 1;
        x >>= 1;
    }
    return pos;
}

// Find the exponential period of the requested interrupt end point.
static inline int usb_get_period(struct usbdevice_s *usbdev, struct usb_endpoint_descriptor *epdesc)
{
    int period = epdesc->bInterval;
    if (usbdev->speed != USB_HIGHSPEED)
        return (period <= 0) ? 0 : __fls(period);
    return (period <= 4) ? 0 : period - 4;
}

int usb_xfer_time(struct usb_pipe *pipe, int datalen);
struct usb_endpoint_descriptor *usb_find_desc(struct usbdevice_s *usbdev, int type, int dir);
void usb_enumerate(struct usbhub_s *hub);

#endif // usb.h
