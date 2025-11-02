#pragma once

#include <libs/aether/evdev.h>

#define CHARACTER_ENTER '\n'
#define CHARACTER_BACK '\b'

struct pipe_node {
    struct usb_pipe *pipe;
    struct pipe_node *next;
};

// hid.c
struct usbdevice_s;
int usb_hid_setup(struct usbdevice_s *usbdev);
int usb_kbd_active(void);
int usb_kbd_command(int command, uint8_t *param);
int usb_mouse_active(void);
int usb_mouse_command(int command, uint8_t *param);
void usb_check_event(void);
