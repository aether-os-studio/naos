// Main code for handling USB controllers and devices.
//
// Copyright (C) 2009-2013  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include <drivers/usb/usb.h>
#include <arch/arch.h>

struct usbdevice_s *usbdevs[MAX_USBDEV_NUM] = {NULL};
usb_driver_t *usb_drivers[MAX_USBDEV_NUM] = {NULL};

void regist_usb_driver(usb_driver_t *driver) {
    for (int i = 0; i < MAX_USBDEV_NUM; i++) {
        if (!usb_drivers[i]) {
            usb_drivers[i] = driver;
            break;
        }
    }
}

static inline void delay(uint64_t ms) {
    uint64_t ns = ms * 1000000ULL;
    uint64_t timeout = nanoTime() + ns;
    while (nanoTime() < timeout) {
        arch_pause();
    }
}

// Allocate, update, or free a usb pipe.
struct usb_pipe *usb_realloc_pipe(struct usbdevice_s *usbdev,
                                  struct usb_pipe *pipe,
                                  struct usb_endpoint_descriptor *epdesc) {
    return usbdev->hub->op->realloc_pipe(usbdev, pipe, epdesc);
}

// Send a message on a control pipe using the default control descriptor.
int usb_send_pipe(struct usb_pipe *pipe_fl, int dir, const void *cmd,
                  void *data, int datasize) {
    return pipe_fl->usbdev->hub->op->send_pipe(pipe_fl, dir, cmd, data,
                                               datasize);
}

int usb_poll_intr(struct usb_pipe *pipe_fl, void *data) {
    return pipe_fl->usbdev->hub->op->poll_intr(pipe_fl, data);
}

int usb_32bit_pipe(struct usb_pipe *pipe_fl) { return 1; }

/****************************************************************
 * Helper functions
 ****************************************************************/

// Allocate a usb pipe.
struct usb_pipe *usb_alloc_pipe(struct usbdevice_s *usbdev,
                                struct usb_endpoint_descriptor *epdesc) {
    return usb_realloc_pipe(usbdev, NULL, epdesc);
}

// Free an allocated control or bulk pipe.
void usb_free_pipe(struct usbdevice_s *usbdev, struct usb_pipe *pipe) {
    if (!pipe)
        return;
    usb_realloc_pipe(usbdev, pipe, NULL);
}

// Send a message to the default control pipe of a device.
int usb_send_default_control(struct usb_pipe *pipe,
                             const struct usb_ctrlrequest *req, void *data) {
    return usb_send_pipe(pipe, req->bRequestType & USB_DIR_IN, req, data,
                         req->wLength);
}

// Send a message to a bulk endpoint
int usb_send_bulk(struct usb_pipe *pipe_fl, int dir, void *data, int datasize) {
    return usb_send_pipe(pipe_fl, dir, NULL, data, datasize);
}

// Check if a pipe for a given controller is on the freelist
int usb_is_freelist(struct usb_s *cntl, struct usb_pipe *pipe) {
    return pipe->cntl != cntl;
}

// Add a pipe to the controller's freelist
void usb_add_freelist(struct usb_pipe *pipe) {
    if (!pipe)
        return;
    struct usb_s *cntl = pipe->cntl;
    pipe->freenext = cntl->freelist;
    cntl->freelist = pipe;
}

// Check for an available pipe on the freelist.
struct usb_pipe *usb_get_freelist(struct usb_s *cntl, uint8_t eptype) {
    struct usb_pipe **pfree = &cntl->freelist;
    for (;;) {
        struct usb_pipe *pipe = *pfree;
        if (!pipe)
            return NULL;
        if (pipe->eptype == eptype) {
            *pfree = pipe->freenext;
            return pipe;
        }
        pfree = &pipe->freenext;
    }
}

// Fill "pipe" endpoint info from an endpoint descriptor.
void usb_desc2pipe(struct usb_pipe *pipe, struct usbdevice_s *usbdev,
                   struct usb_endpoint_descriptor *epdesc) {
    pipe->cntl = usbdev->hub->cntl;
    pipe->type = usbdev->hub->cntl->type;
    pipe->ep = epdesc->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK;
    pipe->devaddr = usbdev->devaddr;
    pipe->speed = usbdev->speed;
    pipe->maxpacket = epdesc->wMaxPacketSize;
    pipe->eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    pipe->usbdev = usbdev;
}

static inline int __fls(unsigned int x) {
    if (x == 0)
        return 0;
    return 32 - __builtin_clz(x);
}

// Find the exponential period of the requested interrupt end point.
int usb_get_period(struct usbdevice_s *usbdev,
                   struct usb_endpoint_descriptor *epdesc) {
    int period = epdesc->bInterval;
    if (usbdev->speed != USB_HIGHSPEED)
        return (period <= 0) ? 0 : __fls(period);
    return (period <= 4) ? 0 : period - 4;
}

// Maximum time (in ms) a data transfer should take
int usb_xfer_time(struct usb_pipe *pipe, int datalen) {
    // Use the maximum command time (5 seconds), except for
    // set_address commands where we don't want to stall the boot if
    // the device doesn't actually exist.  Add 100ms to account for
    // any controller delays.
    if (!pipe->devaddr)
        return USB_TIME_STATUS + 100;
    return USB_TIME_COMMAND + 100;
}

// Find the first endpoint of a given type in an interface description.
struct usb_endpoint_descriptor *usb_find_desc(struct usbdevice_s *usbdev,
                                              int type, int dir) {
    struct usb_endpoint_descriptor *epdesc = (void *)&usbdev->iface[1];
    for (;;) {
        if ((void *)epdesc >= (void *)usbdev->iface + usbdev->imax ||
            epdesc->bDescriptorType == USB_DT_INTERFACE) {
            return NULL;
        }
        if (epdesc->bDescriptorType == USB_DT_ENDPOINT &&
            (epdesc->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == dir &&
            (epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == type)
            return epdesc;
        epdesc = (void *)epdesc + epdesc->bLength;
    }
}

// Get the first 8 bytes of the device descriptor.
static int get_device_info8(struct usb_pipe *pipe,
                            struct usb_device_descriptor *dinfo) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_GET_DESCRIPTOR;
    req.wValue = USB_DT_DEVICE << 8;
    req.wIndex = 0;
    req.wLength = 8;
    return usb_send_default_control(pipe, &req, dinfo);
}

static struct usb_config_descriptor *get_device_config(struct usb_pipe *pipe) {
    struct usb_config_descriptor cfg;

    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_GET_DESCRIPTOR;
    req.wValue = USB_DT_CONFIG << 8;
    req.wIndex = 0;
    req.wLength = sizeof(cfg);
    int ret = usb_send_default_control(pipe, &req, &cfg);
    if (ret)
        return NULL;

    struct usb_config_descriptor *config = malloc(cfg.wTotalLength);
    if (!config) {
        return NULL;
    }
    req.wLength = cfg.wTotalLength;
    ret = usb_send_default_control(pipe, &req, config);
    if (ret || config->wTotalLength != cfg.wTotalLength) {
        free(config);
        return NULL;
    }
    // hexdump(config, cfg.wTotalLength);
    return config;
}

static int set_configuration(struct usb_pipe *pipe, uint16_t val) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_SET_CONFIGURATION;
    req.wValue = val;
    req.wIndex = 0;
    req.wLength = 0;
    return usb_send_default_control(pipe, &req, NULL);
}

/****************************************************************
 * Initialization and enumeration
 ****************************************************************/

static const int speed_to_ctlsize[] = {
    [USB_FULLSPEED] = 8,
    [USB_LOWSPEED] = 8,
    [USB_HIGHSPEED] = 64,
    [USB_SUPERSPEED] = 512,
};

// Assign an address to a device in the default state on the given
// controller.
static int usb_set_address(struct usbdevice_s *usbdev) {
    struct usb_s *cntl = usbdev->hub->cntl;
    if (cntl->maxaddr >= USB_MAXADDR)
        return -1;

    delay(USB_TIME_RSTRCY);

    // Create a pipe for the default address.
    struct usb_endpoint_descriptor epdesc = {
        .wMaxPacketSize = speed_to_ctlsize[usbdev->speed],
        .bmAttributes = USB_ENDPOINT_XFER_CONTROL,
    };
    usbdev->defpipe = usb_alloc_pipe(usbdev, &epdesc);
    if (!usbdev->defpipe)
        return -1;

    // Send set_address command.
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_SET_ADDRESS;
    req.wValue = cntl->maxaddr + 1;
    req.wIndex = 0;
    req.wLength = 0;
    int ret = usb_send_default_control(usbdev->defpipe, &req, NULL);
    if (ret) {
        usb_free_pipe(usbdev, usbdev->defpipe);
        return -1;
    }

    delay(USB_TIME_SETADDR_RECOVERY);

    cntl->maxaddr++;
    usbdev->devaddr = cntl->maxaddr;
    usbdev->defpipe = usb_realloc_pipe(usbdev, usbdev->defpipe, &epdesc);
    if (!usbdev->defpipe)
        return -1;
    return 0;
}

usb_driver_t *usb_find_driver(struct usbdevice_s *usbdev) {
    for (int i = 0; i < MAX_USBDEV_NUM; i++) {
        if (usb_drivers[i] &&
            usb_drivers[i]->class == usbdev->iface->bInterfaceClass) {
            return usb_drivers[i];
        }
    }

    return NULL;
}

// Called for every found device - see if a driver is available for
// this device and do setup if so.
static int configure_usb_device(struct usbdevice_s *usbdev) {
    // Set the max packet size for endpoint 0 of this device.
    struct usb_device_descriptor dinfo;
    memset(&dinfo, 0, sizeof(struct usb_device_descriptor));
    int ret = get_device_info8(usbdev->defpipe, &dinfo);
    if (ret) {
        printk("Failed get device info 8\n");
        return 0;
    }
    printk("USB device descriptor:\n");
    printk("  bLength = %d\n", dinfo.bLength);
    printk("  bDescriptorType = %d\n", dinfo.bDescriptorType);
    printk("  bcdUSB = %#06lx\n", dinfo.bcdUSB);
    printk("  bDeviceClass = %#04lx\n", dinfo.bDeviceClass);
    printk("  bDeviceSubClass = %#04lx\n", dinfo.bDeviceSubClass);
    printk("  bMaxPacketSize0 = %#04lx\n", dinfo.bMaxPacketSize0);
    uint16_t maxpacket = dinfo.bMaxPacketSize0;
    if (dinfo.bcdUSB >= 0x0300)
        maxpacket = 1 << dinfo.bMaxPacketSize0;
    if (maxpacket < 8) {
        printk("Failed get max packet size, maxpacket = %d\n", maxpacket);
        return 0;
    }
    struct usb_endpoint_descriptor epdesc = {
        .wMaxPacketSize = maxpacket,
        .bmAttributes = USB_ENDPOINT_XFER_CONTROL,
    };
    usbdev->defpipe = usb_realloc_pipe(usbdev, usbdev->defpipe, &epdesc);
    if (!usbdev->defpipe) {
        printk("Failed realloc pipe\n");
        return 0;
    }

    delay(100ULL);
    // Get configuration
    struct usb_config_descriptor *config = get_device_config(usbdev->defpipe);
    if (!config) {
        printk("Failed get device configuration\n");
        return 0;
    }

    // Determine if a driver exists for this device - only look at the
    // interfaces of the first configuration.
    int num_iface = config->bNumInterfaces;
    void *config_end = (void *)config + config->wTotalLength;
    struct usb_interface_descriptor *iface = (void *)(&config[1]);
    for (;;) {
        if (!num_iface || (void *)iface + iface->bLength > config_end) {
            printk("Device not support\n");
            goto fail;
        }
        if (iface->bDescriptorType == USB_DT_INTERFACE) {
            num_iface--;
            if (iface->bInterfaceClass == USB_CLASS_HUB ||
                (iface->bInterfaceClass == USB_CLASS_MASS_STORAGE &&
                 (iface->bInterfaceProtocol == US_PR_BULK ||
                  iface->bInterfaceProtocol == US_PR_UAS)) ||
                (iface->bInterfaceClass == USB_CLASS_HID &&
                 iface->bInterfaceSubClass == USB_INTERFACE_SUBCLASS_BOOT))
                break;
        }
        iface = (void *)iface + iface->bLength;
    }

    delay(100ULL);
    printk("Setting configuration (value = %d)\n", config->bConfigurationValue);

    // Set the configuration.
    ret = set_configuration(usbdev->defpipe, config->bConfigurationValue);
    if (ret) {
        printk("Failed set configuration\n");
        goto fail;
    }

    // Configure driver.
    usbdev->config = config;
    usbdev->iface = iface;
    usbdev->imax = (void *)config + config->wTotalLength - (void *)iface;
    // if (iface->bInterfaceClass == USB_CLASS_HUB)
    //     ret = usb_hub_setup(usbdev);
    // else if (iface->bInterfaceClass == USB_CLASS_MASS_STORAGE) {
    //     if (iface->bInterfaceProtocol == US_PR_BULK)
    //         ret = usb_msc_setup(usbdev);
    //     if (iface->bInterfaceProtocol == US_PR_UAS)
    //         ret = usb_uas_setup(usbdev);
    // } else
    //     ret = usb_hid_setup(usbdev);

    usb_driver_t *driver = usb_find_driver(usbdev);
    if (!driver) {
        printk("Failed select best driver for usb device\n");
        goto fail;
    }

    if (driver->probe(usbdev)) {
        printk("Failed probe usb device\n");
        goto fail;
    }

    free(config);
    return 1;
fail:
    free(config);
    return 0;
}

static bool usb_hub_port_setup(struct usbdevice_s *usbdev) {
    struct usbhub_s *hub = usbdev->hub;
    uint32_t port = usbdev->port;

    spin_lock(&hub->cntl->resetlock);

    // Detect if device present (and possibly start reset)
    int ret = hub->op->detect(hub, port);
    if (!ret)
        goto resetfail;

    delay(USB_TIME_ATTDB);

    // Reset port and determine device speed
    ret = hub->op->reset(hub, port);
    if (ret < 0)
        // Reset failed
        goto resetfail;
    usbdev->speed = ret;

    // Set address of port
    ret = usb_set_address(usbdev);
    if (ret) {
        hub->op->disconnect(hub, port);
        goto resetfail;
    }
    spin_unlock(&hub->cntl->resetlock);

    // Configure the device
    int count = configure_usb_device(usbdev);
    usb_free_pipe(usbdev, usbdev->defpipe);
    if (!count) {
        hub->op->disconnect(hub, port);
        printk("Configure device at port %d failed\n", port);
        return false;
    }
    hub->devcount += count;
    printk("Configure device at port %d successfully\n", port);

    for (int i = 0; i < MAX_USBDEV_NUM; i++) {
        if (!usbdevs[i]) {
            usbdevs[i] = usbdev;
            break;
        }
    }

    return true;

resetfail:
    spin_unlock(&hub->cntl->resetlock);
    return false;
}

void usb_enumerate(struct usbhub_s *hub) {
    uint32_t portcount = hub->portcount;

    int i;
    for (i = 0; i < portcount; i++) {
        struct usbdevice_s *usbdev = malloc(sizeof(*usbdev));
        if (!usbdev) {
            continue;
        }
        memset(usbdev, 0, sizeof(*usbdev));
        usbdev->hub = hub;
        usbdev->port = i;
        if (!usb_hub_port_setup(usbdev))
            free(usbdev);
    }
}
