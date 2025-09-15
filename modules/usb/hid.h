#pragma once

#include <libs/aether/evdev.h>

#define CHARACTER_ENTER '\n'
#define CHARACTER_BACK '\b'

struct pipe_node
{
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

extern void push_char(uint8_t ch);

/****************************************************************
 * hid flags
 ****************************************************************/

#define USB_INTERFACE_SUBCLASS_BOOT 1
#define USB_INTERFACE_PROTOCOL_KEYBOARD 1
#define USB_INTERFACE_PROTOCOL_MOUSE 2

#define HID_REQ_GET_REPORT 0x01
#define HID_REQ_GET_IDLE 0x02
#define HID_REQ_GET_PROTOCOL 0x03
#define HID_REQ_SET_REPORT 0x09
#define HID_REQ_SET_IDLE 0x0A
#define HID_REQ_SET_PROTOCOL 0x0B
