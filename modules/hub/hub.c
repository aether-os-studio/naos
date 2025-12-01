#include "hub.h"

static inline void delay(uint64_t ms) {
    uint64_t ns = ms * 1000000ULL;
    uint64_t timeout = nanoTime() + ns;
    while (nanoTime() < timeout) {
        arch_pause();
    }
}

static int get_hub_desc(struct usb_pipe *pipe,
                        struct usb_hub_descriptor *desc) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_DEVICE;
    req.bRequest = USB_REQ_GET_DESCRIPTOR;
    if (pipe->speed == USB_SUPERSPEED)
        req.wValue = USB_DT_HUB3 << 8;
    else
        req.wValue = USB_DT_HUB << 8;
    req.wIndex = 0;
    req.wLength = sizeof(*desc);
    return usb_send_default_control(pipe, &req, desc);
}

static int set_hub_depth(struct usb_pipe *pipe, uint16_t depth) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_DEVICE;
    req.bRequest = HUB_REQ_SET_HUB_DEPTH;
    req.wValue = depth;
    req.wIndex = 0;
    req.wLength = 0;
    return usb_send_default_control(pipe, &req, NULL);
}

static int set_port_feature(struct usbhub_s *hub, int port, int feature) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_SET_FEATURE;
    req.wValue = feature;
    req.wIndex = port + 1;
    req.wLength = 0;
    int ret = usb_send_default_control(hub->usbdev->defpipe, &req, NULL);
    return ret;
}

static int clear_port_feature(struct usbhub_s *hub, int port, int feature) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_CLEAR_FEATURE;
    req.wValue = feature;
    req.wIndex = port + 1;
    req.wLength = 0;
    int ret = usb_send_default_control(hub->usbdev->defpipe, &req, NULL);
    return ret;
}

static int get_port_status(struct usbhub_s *hub, int port,
                           struct usb_port_status *sts) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_GET_STATUS;
    req.wValue = 0;
    req.wIndex = port + 1;
    req.wLength = sizeof(*sts);
    int ret = usb_send_default_control(hub->usbdev->defpipe, &req, sts);
    return ret;
}

// Check if device attached to port
static int usb_hub_detect(struct usbhub_s *hub, uint32_t port) {
    struct usb_port_status sts;
    int ret = get_port_status(hub, port, &sts);
    if (ret) {
        printk("Failure on hub port %d detect\n", port);
        return -1;
    }
    return (sts.wPortStatus & USB_PORT_STAT_CONNECTION) ? 1 : 0;
}

// Disable port
static void usb_hub_disconnect(struct usbhub_s *hub, uint32_t port) {
    int ret = clear_port_feature(hub, port, USB_PORT_FEAT_ENABLE);
    if (ret)
        printk("Failure on hub port %d disconnect\n", port);
}

// Reset device on port
static int usb_hub_reset(struct usbhub_s *hub, uint32_t port) {
    int ret = set_port_feature(hub, port, USB_PORT_FEAT_RESET);
    if (ret)
        goto fail;

    // Wait for reset to complete.
    struct usb_port_status sts;
    uint64_t timeout = nanoTime() + 1000000ULL * USB_TIME_DRST * 2;
    for (;;) {
        ret = get_port_status(hub, port, &sts);
        if (ret)
            goto fail;
        if (!(sts.wPortStatus & USB_PORT_STAT_RESET) &&
            (hub->usbdev->speed != USB_SUPERSPEED ||
             !(sts.wPortStatus & USB_PORT_STAT_LINK_MASK)))
            break;
        if (nanoTime() > timeout) {
            goto fail;
        }
        delay(5);
    }

    // Reset complete.
    if (!(sts.wPortStatus & USB_PORT_STAT_CONNECTION))
        // Device no longer present
        return -1;

    if (hub->usbdev->speed == USB_SUPERSPEED)
        return USB_SUPERSPEED;
    return ((sts.wPortStatus & USB_PORT_STAT_SPEED_MASK) >>
            USB_PORT_STAT_SPEED_SHIFT);

fail:
    printk("Failure on hub port %d reset\n", port);
    usb_hub_disconnect(hub, port);
    return -1;
}

static struct usbhub_op_s usb_hub_op = {
    .detect = usb_hub_detect,
    .reset = usb_hub_reset,
    .disconnect = usb_hub_disconnect,
};

int usb_hub_setup(struct usbdevice_s *usbdev, struct usbdevice_a_interface *iface) {
    usb_hub_op.realloc_pipe = usbdev->hub->op->realloc_pipe;
    usb_hub_op.send_pipe = usbdev->hub->op->send_pipe;
    usb_hub_op.send_intr_pipe = usbdev->hub->op->send_intr_pipe;

    struct usb_hub_descriptor desc;
    int ret = get_hub_desc(usbdev->defpipe, &desc);
    if (ret)
        return ret;

    struct usbhub_s *hub = malloc(sizeof(struct usbhub_s));
    memset(hub, 0, sizeof(struct usbhub_s));
    hub->usbdev = usbdev;
    hub->cntl = usbdev->defpipe->cntl;
    hub->portcount = desc.bNbrPorts;
    hub->op = &usb_hub_op;

    if (usbdev->speed == USB_SUPERSPEED) {
        int depth = 0;
        struct usbdevice_s *parent = usbdev->hub->usbdev;
        while (parent) {
            depth++;
            parent = parent->hub->usbdev;
        }

        ret = set_hub_depth(usbdev->defpipe, depth);
        if (ret)
            return ret;
    }

    // Turn on power to ports.
    int port;
    for (port = 0; port < desc.bNbrPorts; port++) {
        ret = set_port_feature(hub, port, USB_PORT_FEAT_POWER);
        if (ret)
            return ret;
    }

    // Wait for port power to stabilize.
    delay(desc.bPwrOn2PwrGood * 2);

    usb_enumerate(hub);

    printk("Initialized USB HUB (%d ports used)\n", hub->devcount);

    return 0;
}

int usb_hub_remove(struct usbdevice_s *usbdev) { return 0; }

usb_driver_t hid_driver = {
    .class = USB_CLASS_HUB,
    .subclass = 0,
    .probe = usb_hub_setup,
    .remove = usb_hub_remove,
};

__attribute__((visibility("default"))) int dlmain() {
    regist_usb_driver(&hid_driver);

    return 0;
}
