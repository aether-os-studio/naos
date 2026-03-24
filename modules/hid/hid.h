#pragma once

#include <drivers/bus/usb.h>
#include <libs/klibc.h>

#define CHARACTER_ENTER '\n'
#define CHARACTER_BACK '\b'

typedef struct hid_device {
    usb_pipe_t *upipe;
    bool xfer_ok;
} hid_device_t;
