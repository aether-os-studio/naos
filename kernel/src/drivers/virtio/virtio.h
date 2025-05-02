#pragma once

#include <libs/klibc.h>
#include <drivers/bus/pci.h>

#define MAX_VIRTIO_DEV_NUM 256

#define VIRTIO_PCI_CAP_COMMON_CFG 0x0
#define VIRTIO_PCI_CAP_DEVICE_STATUS 0x4
#define VIRTIO_PCI_CAP_QUEUE_NUM 0x8
#define VIRTIO_PCI_CAP_QUEUE_PFN 0xC

// Virtio设备寄存器定义
#define VIRTIO_PCI_HOST_FEATURES 0x00
#define VIRTIO_PCI_GUEST_FEATURES 0x04
#define VIRTIO_PCI_QUEUE_PFN 0x08
#define VIRTIO_PCI_QUEUE_SIZE 0x0C
#define VIRTIO_PCI_QUEUE_SELECT 0x0E
#define VIRTIO_PCI_QUEUE_NOTIFY 0x10
#define VIRTIO_PCI_STATUS 0x12
#define VIRTIO_PCI_ISR 0x13

// 设备状态标志
#define VIRTIO_STATUS_RESET 0x00
#define VIRTIO_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_STATUS_DRIVER 0x02
#define VIRTIO_STATUS_DRIVER_OK 0x04

typedef struct input_event
{
    uint16_t type;
    uint16_t code;
    uint32_t value;
} input_event_t;

void virtio_init();
