#include "msc.h"
#include "hid.h"
#include "usb.h"

/****************************************************************
 * Controller function wrappers
 ****************************************************************/

// Send a message on a control pipe using the default control descriptor.
int usb_send_pipe(struct usb_pipe *pipe_fl, int dir, const void *cmd, void *data, int datasize)
{
    switch (GET_LOWFLAT(pipe_fl->type))
    {
    default:
    // case USB_TYPE_UHCI:
    //     return uhci_send_pipe(pipe_fl, dir, cmd, data, datasize);
    // case USB_TYPE_OHCI:
    //     if (MODESEGMENT)
    //         return -1;
    //     return ohci_send_pipe(pipe_fl, dir, cmd, data, datasize);
    // case USB_TYPE_EHCI:
    //     return ehci_send_pipe(pipe_fl, dir, cmd, data, datasize);
    case USB_TYPE_XHCI:
        // if (MODESEGMENT)
        //     return -1;
        return xhci_send_pipe(pipe_fl, dir, cmd, data, datasize);
    }
}

int usb_poll_intr(struct usb_pipe *pipe_fl, void *data)
{
    switch (GET_LOWFLAT(pipe_fl->type))
    {
    default:
    // case USB_TYPE_UHCI:
    //     return uhci_poll_intr(pipe_fl, data);
    // case USB_TYPE_OHCI:
    //     return ohci_poll_intr(pipe_fl, data);
    // case USB_TYPE_EHCI:
    //     return ehci_poll_intr(pipe_fl, data);
    case USB_TYPE_XHCI:;
        return xhci_poll_intr(pipe_fl, data);
    }
}

int usb_32bit_pipe(struct usb_pipe *pipe_fl)
{
    return true;
}

/****************************************************************
 * Helper functions
 ****************************************************************/

// Send a message to the default control pipe of a device.
int usb_send_default_control(struct usb_pipe *pipe, const struct usb_ctrlrequest *req, void *data)
{
    return usb_send_pipe(pipe, req->bRequestType & USB_DIR_IN, req, data, req->wLength);
}

// Send a message to a bulk endpoint
int usb_send_bulk(struct usb_pipe *pipe_fl, int dir, void *data, int datasize)
{
    return usb_send_pipe(pipe_fl, dir, NULL, data, datasize);
}

// Check if a pipe for a given controller is on the freelist
int usb_is_freelist(struct usb_s *cntl, struct usb_pipe *pipe)
{
    return pipe->cntl != cntl;
}

// Add a pipe to the controller's freelist
void usb_add_freelist(struct usb_pipe *pipe)
{
    if (!pipe)
        return;
    struct usb_s *cntl = pipe->cntl;
    pipe->freenext = cntl->freelist;
    cntl->freelist = pipe;
}

// Check for an available pipe on the freelist.
struct usb_pipe *
usb_get_freelist(struct usb_s *cntl, uint8_t eptype)
{
    struct usb_pipe **pfree = &cntl->freelist;
    for (;;)
    {
        struct usb_pipe *pipe = *pfree;
        if (!pipe)
            return NULL;
        if (pipe->eptype == eptype)
        {
            *pfree = pipe->freenext;
            return pipe;
        }
        pfree = &pipe->freenext;
    }
}

// Fill "pipe" endpoint info from an endpoint descriptor.
void usb_desc2pipe(struct usb_pipe *pipe, struct usbdevice_s *usbdev, struct usb_endpoint_descriptor *epdesc)
{
    pipe->cntl = usbdev->hub->cntl;
    pipe->type = usbdev->hub->cntl->type;
    pipe->ep = epdesc->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK;
    pipe->devaddr = usbdev->devaddr;
    pipe->speed = usbdev->speed;
    pipe->maxpacket = epdesc->wMaxPacketSize;
    pipe->eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
}

// Maximum time (in ms) a data transfer should take
int usb_xfer_time(struct usb_pipe *pipe, int datalen)
{
    // Use the maximum command time (5 seconds), except for
    // set_address commands where we don't want to stall the boot if
    // the device doesn't actually exist.  Add 100ms to account for
    // any controller delays.
    if (!GET_LOWFLAT(pipe->devaddr))
        return USB_TIME_STATUS + 100;
    return USB_TIME_COMMAND + 100;
}

// Find the first endpoint of a given type in an interface description.
struct usb_endpoint_descriptor *
usb_find_desc(struct usbdevice_s *usbdev, int type, int dir)
{
    struct usb_endpoint_descriptor *epdesc = (void *)&usbdev->iface[1];
    for (;;)
    {
        if ((void *)epdesc >= (void *)usbdev->iface + usbdev->imax || epdesc->bDescriptorType == USB_DT_INTERFACE)
        {
            return NULL;
        }
        if (epdesc->bDescriptorType == USB_DT_ENDPOINT && (epdesc->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == dir && (epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == type)
            return epdesc;
        epdesc = (void *)epdesc + epdesc->bLength;
    }
}

// Get the first 8 bytes of the device descriptor.
static int
get_device_info8(struct usb_pipe *pipe, struct usb_device_descriptor *dinfo)
{
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_GET_DESCRIPTOR;
    req.wValue = USB_DT_DEVICE << 8;
    req.wIndex = 0;
    req.wLength = 8;
    return usb_send_default_control(pipe, &req, dinfo);
}

static struct usb_config_descriptor *
get_device_config(struct usb_pipe *pipe)
{
    struct usb_config_descriptor cfg;

    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_GET_DESCRIPTOR;
    req.wValue = USB_DT_CONFIG << 8;
    req.wIndex = 0;
    req.wLength = sizeof(cfg);
    int ret = usb_send_default_control(pipe, &req, &cfg);
    if (ret)
    {
        printf("[usb.c:%d] Failed to get configuration descriptor: usb_send_default_control\n", __LINE__);
        return NULL;
    }

    struct usb_config_descriptor *config = malloc(cfg.wTotalLength);
    if (!config)
    {
        printf("[usb.c:%d] Failed to get configuration descriptor: malloc\n", __LINE__);
        return NULL;
    }
    req.wLength = cfg.wTotalLength;
    ret = usb_send_default_control(pipe, &req, config);
    if (ret)
    {
        printf("[usb.c:%d] Failed to get configuration descriptor: usb_send_default_control\n", __LINE__);
        free(config);
        return NULL;
    }
    if (config->wTotalLength != cfg.wTotalLength)
    {
        printf("[usb.c:%d] Failed to get configuration descriptor: config->wTotalLength != cfg.wTotalLength\tconfig->wTotalLength = %d, cfg.wTotalLength = %d", __LINE__, config->wTotalLength, cfg.wTotalLength);
        free(config);
        return NULL;
    }
    // hexdump(config, cfg.wTotalLength);
    return config;
}

static int
set_configuration(struct usb_pipe *pipe, uint16_t val)
{
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
static int
usb_set_address(struct usbdevice_s *usbdev)
{
    struct usb_s *cntl = usbdev->hub->cntl;
    if (cntl->maxaddr >= USB_MAXADDR)
        return -1;

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
    if (ret)
    {
        usb_free_pipe(usbdev, usbdev->defpipe);
        return -1;
    }

    cntl->maxaddr++;
    usbdev->devaddr = cntl->maxaddr;
    usbdev->defpipe = usb_realloc_pipe(usbdev, usbdev->defpipe, &epdesc);
    if (!usbdev->defpipe)
        return -1;
    return 0;
}

// Called for every found device - see if a driver is available for
// this device and do setup if so.
static int configure_usb_device(struct usbdevice_s *usbdev)
{
    // Set the max packet size for endpoint 0 of this device.
    struct usb_device_descriptor dinfo;
    int ret = get_device_info8(usbdev->defpipe, &dinfo);
    if (ret)
        return 0;
    uint16_t maxpacket = dinfo.bMaxPacketSize0;
    if (dinfo.bcdUSB >= 0x0300)
        maxpacket = 1 << dinfo.bMaxPacketSize0;
    if (maxpacket < 8)
        return 0;
    struct usb_endpoint_descriptor epdesc = {
        .wMaxPacketSize = maxpacket,
        .bmAttributes = USB_ENDPOINT_XFER_CONTROL,
    };
    usbdev->defpipe = usb_realloc_pipe(usbdev, usbdev->defpipe, &epdesc);
    if (!usbdev->defpipe)
    {
        printf("Failed to reallocate control pipe for USB device\n");
        return -1;
    }

    // Get configuration
    struct usb_config_descriptor *config = get_device_config(usbdev->defpipe);
    if (!config)
    {
        printf("[usb.c:%d] Failed to get configuration descriptor for USB device\n", __LINE__);
        return 0;
    }

    // Determine if a driver exists for this device - only look at the
    // interfaces of the first configuration.
    int num_iface = config->bNumInterfaces;
    void *config_end = (void *)config + config->wTotalLength;
    struct usb_interface_descriptor *iface = (void *)(&config[1]);
    for (;;)
    {
        if (!num_iface || (void *)iface + iface->bLength > config_end)
            // Not a supported device.
            goto fail;
        if (iface->bDescriptorType == USB_DT_INTERFACE)
        {
            num_iface--;
            if (iface->bInterfaceClass == USB_CLASS_HUB || (iface->bInterfaceClass == USB_CLASS_MASS_STORAGE && (iface->bInterfaceProtocol == US_PR_BULK || iface->bInterfaceProtocol == US_PR_UAS)) || (iface->bInterfaceClass == USB_CLASS_HID && iface->bInterfaceSubClass == USB_INTERFACE_SUBCLASS_BOOT))
                break;
        }
        iface = (void *)iface + iface->bLength;
    }

    // Set the configuration.
    ret = set_configuration(usbdev->defpipe, config->bConfigurationValue);
    if (ret)
        goto fail;

    // Configure driver.
    usbdev->config = config;
    usbdev->iface = iface;
    usbdev->imax = (void *)config + config->wTotalLength - (void *)iface;
    if (iface->bInterfaceClass == USB_CLASS_HUB)
    {
        printf("hub device detected\n");
    }
    else if (iface->bInterfaceClass == USB_CLASS_MASS_STORAGE)
    {
        printf("mass storage device detected\n");
        if (iface->bInterfaceProtocol == US_PR_BULK)
            ret = usb_msc_setup(usbdev);
        if (iface->bInterfaceProtocol == US_PR_UAS)
            printf("unsupported USB device: UAS\n");
        //     ret = usb_uas_setup(usbdev);
    }
    else if (iface->bInterfaceClass == USB_CLASS_HID)
    {
        printk("hid device detected\n");
        ret = usb_hid_setup(usbdev);
    }
    else
    {
        goto fail;
    }
    if (ret)
        goto fail;

    free(config);
    return 1;
fail:
    free(config);
    return 0;
}

static void
usb_hub_port_setup(void *data)
{
    struct usbdevice_s *usbdev = data;
    struct usbhub_s *hub = usbdev->hub;
    uint32_t port = usbdev->port;

    for (;;)
    {
        // Detect if device present (and possibly start reset)
        int ret = hub->op->detect(hub, port);
        if (ret > 0)
        {
            printf("USB device found at port %d\n", port);
            // Device connected.
            break;
        }
        if (ret <= 0)
        {
            printf("No device found at port %d\n", port);
            // No device found.
            goto done;
        }
    }

    // XXX - wait USB_TIME_ATTDB time?

    // Reset port and determine device speed
    spin_lock(&hub->cntl->resetlock);
    int ret = hub->op->reset(hub, port);
    if (ret < 0)
    {
        // Reset failed
        printf("Failed to reset USB device at port %d\n", port);
        goto resetfail;
    }
    usbdev->speed = ret;

    // Set address of port
    ret = usb_set_address(usbdev);
    if (ret)
    {
        printf("Failed to set USB device address at port %d\n", port);
        hub->op->disconnect(hub, port);
        goto resetfail;
    }
    spin_unlock(&hub->cntl->resetlock);

    // Configure the device
    int count = configure_usb_device(usbdev);
    usb_free_pipe(usbdev, usbdev->defpipe);
    if (!count)
        hub->op->disconnect(hub, port);
    hub->devcount += count;
done:
    hub->threads--;
    free(usbdev);
    return;

resetfail:
    printf("Reset USB device failed at port %d\n", port);
    spin_unlock(&hub->cntl->resetlock);
    goto done;
}

static uint32_t usb_time_sigatt;

void usb_enumerate(struct usbhub_s *hub)
{
    uint32_t portcount = hub->portcount;
    hub->threads = portcount;

    // Launch a thread for every port.
    int i;
    for (i = 0; i < portcount; i++)
    {
        struct usbdevice_s *usbdev = malloc(sizeof(*usbdev));
        if (!usbdev)
        {
            continue;
        }
        memset(usbdev, 0, sizeof(*usbdev));
        usbdev->hub = hub;
        usbdev->port = i;
        usb_hub_port_setup(usbdev);
    }

    // Wait for threads to complete.
    while (hub->threads)
        arch_pause();
}
