#include "hub.h"

static inline void delay(uint64_t ms) {
    uint64_t ns = ms * 1000000ULL;
    uint64_t timeout = nano_time() + ns;
    while (nano_time() < timeout) {
        arch_pause();
    }
}

static int get_hub_desc(usb_pipe_t *pipe, usb_hub_descriptor_t *desc) {
    usb_ctrl_request_t req;
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

static int set_hub_depth(usb_pipe_t *pipe, uint16_t depth) {
    usb_ctrl_request_t req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_DEVICE;
    req.bRequest = HUB_REQ_SET_HUB_DEPTH;
    req.wValue = depth;
    req.wIndex = 0;
    req.wLength = 0;
    return usb_send_default_control(pipe, &req, NULL);
}

static int set_port_feature(usb_hub_t *hub, int port, int feature) {
    usb_ctrl_request_t req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_SET_FEATURE;
    req.wValue = feature;
    req.wIndex = port + 1;
    req.wLength = 0;
    int ret = usb_send_default_control(hub->usbdev->defpipe, &req, NULL);
    return ret;
}

static int clear_port_feature(usb_hub_t *hub, int port, int feature) {
    usb_ctrl_request_t req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_CLEAR_FEATURE;
    req.wValue = feature;
    req.wIndex = port + 1;
    req.wLength = 0;
    int ret = usb_send_default_control(hub->usbdev->defpipe, &req, NULL);
    return ret;
}

static int get_port_status(usb_hub_t *hub, int port, usb_port_status_t *sts) {
    usb_ctrl_request_t req;
    req.bRequestType = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_OTHER;
    req.bRequest = USB_REQ_GET_STATUS;
    req.wValue = 0;
    req.wIndex = port + 1;
    req.wLength = sizeof(*sts);
    int ret = usb_send_default_control(hub->usbdev->defpipe, &req, sts);
    return ret;
}

// Check if device attached to port
static int usb_hub_detect(usb_hub_t *hub, uint32_t port) {
    usb_port_status_t sts;
    int ret = get_port_status(hub, port, &sts);
    if (ret) {
        printk("Failure on hub port %d detect\n", port);
        return -1;
    }
    return (sts.wPortStatus & USB_PORT_STAT_CONNECTION) ? 1 : 0;
}

// Disable port
static void usb_hub_disconnect(usb_hub_t *hub, uint32_t port) {
    int ret = clear_port_feature(hub, port, USB_PORT_FEAT_ENABLE);
    if (ret)
        printk("Failure on hub port %d disconnect\n", port);
}

// Reset device on port
static int usb_hub_reset(usb_hub_t *hub, uint32_t port) {
    int ret = set_port_feature(hub, port, USB_PORT_FEAT_RESET);
    if (ret)
        goto fail;

    // Wait for reset to complete.
    usb_port_status_t sts;
    uint64_t timeout = nano_time() + 1000000ULL * USB_TIME_DRST * 2;
    for (;;) {
        ret = get_port_status(hub, port, &sts);
        if (ret)
            goto fail;
        if (!(sts.wPortStatus & USB_PORT_STAT_RESET) &&
            (hub->usbdev->speed != USB_SUPERSPEED ||
             !(sts.wPortStatus & USB_PORT_STAT_LINK_MASK)))
            break;
        if (nano_time() > timeout) {
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

static usb_hub_ops_t usb_hub_op = {
    .detect = usb_hub_detect,
    .reset = usb_hub_reset,
    .disconnect = usb_hub_disconnect,
};

int usb_hub_setup(usb_device_t *usbdev, usb_device_interface_t *iface) {
    usb_hub_op.realloc_pipe = usbdev->hub->op->realloc_pipe;
    usb_hub_op.send_pipe = usbdev->hub->op->send_pipe;
    usb_hub_op.send_intr_pipe = usbdev->hub->op->send_intr_pipe;

    usb_hub_descriptor_t desc;
    int ret = get_hub_desc(usbdev->defpipe, &desc);
    if (ret)
        return ret;

    usb_hub_t *hub = malloc(sizeof(usb_hub_t));
    memset(hub, 0, sizeof(usb_hub_t));
    hub->usbdev = usbdev;
    hub->cntl = usbdev->defpipe->cntl;
    hub->portcount = desc.bNbrPorts;
    hub->op = &usb_hub_op;
    usbdev->childhub = hub;

    if (usbdev->speed == USB_SUPERSPEED) {
        int depth = 0;
        usb_device_t *parent = usbdev->hub->usbdev;
        while (parent && !parent->is_root_hub) {
            depth++;
            parent = parent->hub->usbdev;
        }

        ret = set_hub_depth(usbdev->defpipe, depth);
        if (ret) {
            usbdev->childhub = NULL;
            free(hub);
            return ret;
        }
    }

    // Turn on power to ports.
    int port;
    for (port = 0; port < desc.bNbrPorts; port++) {
        ret = set_port_feature(hub, port, USB_PORT_FEAT_POWER);
        if (ret) {
            usbdev->childhub = NULL;
            free(hub);
            return ret;
        }
    }

    // Wait for port power to stabilize.
    delay(desc.bPwrOn2PwrGood * 2);

    usb_enumerate(hub);

    printk("Initialized USB HUB (%d ports used)\n", hub->devcount);

    return 0;
}

int usb_hub_remove(usb_device_t *usbdev) { return 0; }

usb_driver_t hub_driver = {
    .class = USB_CLASS_HUB,
    .subclass = 0,
    .probe = usb_hub_setup,
    .remove = usb_hub_remove,
};

int dlmain() {
    regist_usb_driver(&hub_driver);

    return 0;
}
