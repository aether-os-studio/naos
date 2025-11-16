#pragma once

#include <libs/klibc.h>
#include <libs/aether/usb.h>
#include <libs/aether/mm.h>

#define USB_DT_HUB (USB_TYPE_CLASS | 0x09)
#define USB_DT_HUB3 (USB_TYPE_CLASS | 0x0a)

#define HUB_REQ_SET_HUB_DEPTH 0x0C

struct usb_hub_descriptor {
    uint8_t bDescLength;
    uint8_t bDescriptorType;
    uint8_t bNbrPorts;
    uint16_t wHubCharacteristics;
    uint8_t bPwrOn2PwrGood;
    uint8_t bHubContrCurrent;
    // Variable length fields for DeviceRemovable[], PortPwrCtrlMask[] follow.
} __attribute__((packed));

#define USB_PORT_FEAT_CONNECTION 0
#define USB_PORT_FEAT_ENABLE 1
#define USB_PORT_FEAT_SUSPEND 2
#define USB_PORT_FEAT_OVER_CURRENT 3
#define USB_PORT_FEAT_RESET 4
#define USB_PORT_FEAT_POWER 8
#define USB_PORT_FEAT_LOWSPEED 9
#define USB_PORT_FEAT_C_CONNECTION 16
#define USB_PORT_FEAT_C_ENABLE 17
#define USB_PORT_FEAT_C_SUSPEND 18
#define USB_PORT_FEAT_C_OVER_CURRENT 19
#define USB_PORT_FEAT_C_RESET 20
#define USB_PORT_FEAT_TEST 21
#define USB_PORT_FEAT_INDICATOR 22
#define USB_PORT_FEAT_C_PORT_L1 23

struct usb_port_status {
    uint16_t wPortStatus;
    uint16_t wPortChange;
} __attribute__((packed));

#define USB_PORT_STAT_CONNECTION 0x0001
#define USB_PORT_STAT_ENABLE 0x0002
#define USB_PORT_STAT_SUSPEND 0x0004
#define USB_PORT_STAT_OVERCURRENT 0x0008
#define USB_PORT_STAT_RESET 0x0010
#define USB_PORT_STAT_LINK_SHIFT 5
#define USB_PORT_STAT_LINK_MASK (0x7 << USB_PORT_STAT_LINK_SHIFT)
#define USB_PORT_STAT_POWER 0x0100
#define USB_PORT_STAT_SPEED_SHIFT 9
#define USB_PORT_STAT_SPEED_MASK (0x3 << USB_PORT_STAT_SPEED_SHIFT)
#define USB_PORT_STAT_LOW_SPEED 0x0200
#define USB_PORT_STAT_HIGH_SPEED 0x0400
#define USB_PORT_STAT_TEST 0x0800
#define USB_PORT_STAT_INDICATOR 0x1000
