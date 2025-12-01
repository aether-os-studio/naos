#pragma once

#include <libs/aether/evdev.h>

#define CHARACTER_ENTER '\n'
#define CHARACTER_BACK '\b'

struct hiddevice_s {
    struct usb_pipe *upipe;
    bool xfer_ok;
};

// hid.c
struct usbdevice_s;
