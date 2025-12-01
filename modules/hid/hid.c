// Code for handling USB Human Interface Devices (HID).
//
// Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
// Copyright (C) 2024  Daniel Khodabakhsh <d.khodabakhsh@gmail.com>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "hid.h"
#include <libs/aether/usb.h>
#include <libs/aether/evdev.h>
#include <libs/aether/input.h>
#include <libs/aether/stdio.h>

/****************************************************************
 * Setup
 ****************************************************************/

// Send USB HID protocol message.
static int set_protocol(struct usb_pipe *pipe, uint16_t val,
                        uint16_t inferface) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    req.bRequest = HID_REQ_SET_PROTOCOL;
    req.wValue = val;
    req.wIndex = inferface;
    req.wLength = 0;
    return usb_send_default_control(pipe, &req, NULL);
}

// Send USB HID SetIdle request.
static int set_idle(struct usb_pipe *pipe, int ms) {
    struct usb_ctrlrequest req;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    req.bRequest = HID_REQ_SET_IDLE;
    req.wValue = (ms / 4) << 8;
    req.wIndex = 0;
    req.wLength = 0;
    return usb_send_default_control(pipe, &req, NULL);
}

#define KEYREPEATWAITMS 500
#define KEYREPEATMS 33

// Format of USB keyboard event data
struct keyevent {
    uint8_t modifiers;
    uint8_t reserved;
    uint8_t keys[6];
};

#define MAX_KBD_EVENT 16

static void usb_check_key(struct hiddevice_s *hid);

static int usb_kbd_setup(struct usbdevice_s *usbdev,
                         struct usb_endpoint_descriptor *epdesc) {
    if (epdesc->wMaxPacketSize < sizeof(struct keyevent) ||
        epdesc->wMaxPacketSize > MAX_KBD_EVENT) {
        return -1;
    }

    // Enable "boot" protocol.
    if (set_protocol(usbdev->defpipe, 0, usbdev->iface->bInterfaceNumber)) {
        return -1;
    }

    // Periodically send reports to enable key repeat.
    if (set_idle(usbdev->defpipe, KEYREPEATMS))
        return -1;

    struct hiddevice_s *hid = malloc(sizeof(struct hiddevice_s));
    hid->upipe = usb_alloc_pipe(usbdev, epdesc);
    if (!hid->upipe) {
        free(hid);
        return -1;
    }
    hid->xfer_ok = false;

    dev_input_event_t *event =
        regist_input_dev("usbkbd", "/sys/devices/usb/input0",
                         "ID_INPUT_KEYBOARD=1", kb_event_bit);
    set_kb_input_event(event);

    task_create("usb_check_key", (void (*)(uint64_t))usb_check_key,
                (uint64_t)hid, KTHREAD_PRIORITY);

    return 0;
}

// // Format of USB mouse event data
// struct mouseevent
// {
//     uint8_t buttons;
//     uint8_t x, y;
// };

// #define MAX_MOUSE_EVENT 8

// static int usb_mouse_setup(struct usbdevice_s *usbdev, struct
// usb_endpoint_descriptor *epdesc)
// {
//     if (epdesc->wMaxPacketSize < sizeof(struct mouseevent) ||
//     epdesc->wMaxPacketSize > MAX_MOUSE_EVENT)
//     {
//         return -1;
//     }

//     // Enable "boot" protocol.
//     if (set_protocol(usbdev->defpipe, 0, usbdev->iface->bInterfaceNumber))
//         return -1;

//     if (add_pipe_node(&mice, usbdev, epdesc))
//         return -1;

//     return 0;
// }

/****************************************************************
 * Keyboard events
 ****************************************************************/

// Mapping from USB key id to ps2 key sequence.
static uint16_t KeyToScanCode[] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x001e, 0x0030, 0x002e, 0x0020, 0x0012,
    0x0021, 0x0022, 0x0023, 0x0017, 0x0024, 0x0025, 0x0026, 0x0032, 0x0031,
    0x0018, 0x0019, 0x0010, 0x0013, 0x001f, 0x0014, 0x0016, 0x002f, 0x0011,
    0x002d, 0x0015, 0x002c, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x0009, 0x000a, 0x000b, 0x001c, 0x0001, 0x000e, 0x000f, 0x0039,
    0x000c, 0x000d, 0x001a, 0x001b, 0x002b, 0x0000, 0x0027, 0x0028, 0x0029,
    0x0033, 0x0034, 0x0035, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f,
    0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0057, 0x0058, 0xe037, 0x0046,
    0xe145, 0xe052, 0xe047, 0xe049, 0xe053, 0xe04f, 0xe051, 0xe04d, 0xe04b,
    0xe050, 0xe048, 0x0045, 0xe035, 0x0037, 0x004a, 0x004e, 0xe01c, 0x004f,
    0x0050, 0x0051, 0x004b, 0x004c, 0x004d, 0x0047, 0x0048, 0x0049, 0x0052,
    0x0053};

// Mapping from USB modifier id to ps2 key sequence.
static uint16_t ModifierToScanCode[] = {
    // lcntl, lshift, lalt, lgui, rcntl, rshift, ralt, rgui
    0x001d, 0x002a, 0x0038, 0xe05b, 0xe01d, 0x0036, 0xe038, 0xe05c};

#define RELEASEBIT 0x80

struct usbkeyinfo {
    union {
        struct {
            uint8_t modifiers;
            uint8_t repeatcount;
            uint8_t keys[6];
        };
        uint64_t data;
    };
};

struct usbkeyinfo LastUSBkey;

#define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))

// Process USB keyboard data.
static void handle_key(struct keyevent *data) {
    static bool ctrlPressed = false;
    static bool shiftPressed = false;

    struct usbkeyinfo old;
    old.data = LastUSBkey.data;

    int addpos = 0;
    int i;
    for (i = 0; i < ARRAY_SIZE(old.keys); i++) {
        uint8_t key = old.keys[i];
        if (!key)
            break;
        int j;
        for (j = 0;; j++) {
            if (j >= ARRAY_SIZE(data->keys)) {
                // Key released.
                // procscankey(key, RELEASEBIT, data->modifiers);
                // printk("Key released\n");
                if (i + 1 >= ARRAY_SIZE(old.keys) || !old.keys[i + 1])
                    // Last pressed key released - disable repeat.
                    old.repeatcount = 0xff;
                break;
            }
            if (data->keys[j] == key) {
                // Key still pressed.
                data->keys[j] = 0;
                old.keys[addpos++] = key;
                break;
            }
        }
    }

    old.modifiers = data->modifiers;

    bool shift = (data->modifiers & (0x02 | 0x20)) != 0;
    if (shift && !shiftPressed) {
        handle_kb_scancode(0x2A, true);
        shiftPressed = true;
    } else if (!shift && shiftPressed) {
        handle_kb_scancode(0x2A, false);
        shiftPressed = false;
    }

    for (i = 0; i < ARRAY_SIZE(data->keys); i++) {
        uint8_t key = data->keys[i];
        if (!key)
            continue;
        // New key pressed.
        uint16_t scancode = KeyToScanCode[key];
        handle_kb_scancode(scancode, true);
        handle_kb_scancode(scancode, false);

        old.keys[addpos++] = key;
        old.repeatcount = KEYREPEATWAITMS / KEYREPEATMS + 1;
    }
    if (addpos < ARRAY_SIZE(old.keys))
        old.keys[addpos] = 0;

    // Check for key repeat event.
    if (addpos) {
        if (!old.repeatcount) {
        } else if (old.repeatcount != 0xff)
            old.repeatcount--;
    }

    LastUSBkey.data = old.data;
}

static void key_cb(int status, void *user_data) {
    struct hiddevice_s *hid = user_data;
    hid->xfer_ok = true;
}

// Check if a USB keyboard event is pending and process it if so.
static void usb_check_key(struct hiddevice_s *hid) {
    uint8_t data[MAX_KBD_EVENT];

    for (;;) {
        int ret =
            usb_send_intr_pipe(hid->upipe, data, sizeof(data), key_cb, hid);
        if (ret)
            break;

        while (!hid->xfer_ok) {
            arch_enable_interrupt();
            arch_yield();
        }
        hid->xfer_ok = false;

        handle_key((void *)data);
    }
}

// Format of USB mouse event data
struct mouseevent {
    uint8_t buttons;
    uint8_t x, y;
};

#define MAX_MOUSE_EVENT 8

static void handle_mouse(struct mouseevent *data) {
    int8_t x = data->x, y = data->y;
    uint8_t flag = data->buttons & 0x7;

    handle_mouse_event(flag, x, y, 0);
}

static void mouse_cb(int status, void *user_data) {
    struct hiddevice_s *hid = user_data;
    hid->xfer_ok = true;
}

static void usb_check_mouse(struct hiddevice_s *hid) {
    uint8_t data[MAX_MOUSE_EVENT];

    for (;;) {
        int ret =
            usb_send_intr_pipe(hid->upipe, data, sizeof(data), mouse_cb, hid);
        if (ret)
            break;

        while (!hid->xfer_ok) {
            arch_enable_interrupt();
            arch_yield();
        }
        hid->xfer_ok = false;

        handle_mouse((void *)data);
    }
}

static int usb_mouse_setup(struct usbdevice_s *usbdev,
                           struct usb_endpoint_descriptor *epdesc) {
    if (epdesc->wMaxPacketSize < sizeof(struct mouseevent) ||
        epdesc->wMaxPacketSize > MAX_MOUSE_EVENT) {
        printk("USB mouse wMaxPacketSize=%d; aborting\n",
               epdesc->wMaxPacketSize);
        return -1;
    }

    // Enable "boot" protocol.
    if (set_protocol(usbdev->defpipe, 0, usbdev->iface->bInterfaceNumber))
        return -1;

    struct hiddevice_s *hid = malloc(sizeof(struct hiddevice_s));
    hid->upipe = usb_alloc_pipe(usbdev, epdesc);
    if (!hid->upipe) {
        free(hid);
        return -1;
    }
    hid->xfer_ok = false;

    dev_input_event_t *event =
        regist_input_dev("usbmouse", "/sys/devices/usb/input1",
                         "ID_INPUT_MOUSE=1", mouse_event_bit);
    set_mouse_input_event(event);

    task_create("usb_check_mouse", (void (*)(uint64_t))usb_check_mouse,
                (uint64_t)hid, KTHREAD_PRIORITY);

    return 0;
}

// Initialize a found USB HID device (if applicable).
int usb_hid_setup(struct usbdevice_s *usbdev) {
    struct usb_interface_descriptor *iface = usbdev->iface;
    if (iface->bInterfaceSubClass != USB_INTERFACE_SUBCLASS_BOOT)
        // Doesn't support boot protocol.
        return -1;

    // Find intr in endpoint.
    struct usb_endpoint_descriptor *epdesc =
        usb_find_desc(usbdev, USB_ENDPOINT_XFER_INT, USB_DIR_IN);
    if (!epdesc) {
        return -1;
    }

    if (iface->bInterfaceProtocol == USB_INTERFACE_PROTOCOL_KEYBOARD)
        return usb_kbd_setup(usbdev, epdesc);
    if (iface->bInterfaceProtocol == USB_INTERFACE_PROTOCOL_MOUSE)
        return usb_mouse_setup(usbdev, epdesc);
    return -1;
}

int usb_hid_remove(struct usbdevice_s *usbdev) { return 0; }

usb_driver_t hid_driver = {
    .class = USB_CLASS_HID,
    .subclass = 0,
    .probe = usb_hid_setup,
    .remove = usb_hid_remove,
};

__attribute__((visibility("default"))) int dlmain() {
    regist_usb_driver(&hid_driver);

    return 0;
}
