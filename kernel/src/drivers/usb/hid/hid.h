#pragma once

#include <drivers/usb/xhci.h>

uint32_t ConfigureHID(USB_COMMON *);
void usb_keyboard_event();
