#pragma once

#include "virtio.h"
#if !defined(__x86_64__)
#include <libs/aether/fdt.h>
#endif

/* VirtIO MMIO 寄存器偏移 */
#define VIRTIO_MMIO_MAGIC_VALUE 0x000
#define VIRTIO_MMIO_VERSION 0x004
#define VIRTIO_MMIO_DEVICE_ID 0x008
#define VIRTIO_MMIO_VENDOR_ID 0x00c
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014
/* Reserved: 0x018, 0x01c */
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024

/* Legacy 模式专用寄存器 (VirtIO 1.0 之前) */
#define VIRTIO_MMIO_LEGACY_GUEST_PAGE_SIZE 0x028
/* Reserved: 0x02c */

#define VIRTIO_MMIO_QUEUE_SEL 0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX 0x034
#define VIRTIO_MMIO_QUEUE_NUM 0x038

/* Legacy 模式专用寄存器 */
#define VIRTIO_MMIO_LEGACY_QUEUE_ALIGN 0x03c
#define VIRTIO_MMIO_LEGACY_QUEUE_PFN 0x040

/* Modern 模式 (VirtIO 1.0+) */
#define VIRTIO_MMIO_QUEUE_READY 0x044
/* Reserved: 0x048, 0x04c */

#define VIRTIO_MMIO_QUEUE_NOTIFY 0x050
/* Reserved: 0x054, 0x058, 0x05c */

#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060
#define VIRTIO_MMIO_INTERRUPT_ACK 0x064
/* Reserved: 0x068, 0x06c */

#define VIRTIO_MMIO_STATUS 0x070
/* Reserved: 0x074, 0x078, 0x07c */

/* Modern 模式队列地址寄存器 */
#define VIRTIO_MMIO_QUEUE_DESC_LOW 0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084
/* Reserved: 0x088, 0x08c */

#define VIRTIO_MMIO_QUEUE_DRIVER_LOW 0x090 // Available Ring
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH 0x094
/* Reserved: 0x098, 0x09c */

#define VIRTIO_MMIO_QUEUE_DEVICE_LOW 0x0a0 // Used Ring
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH 0x0a4
/* Reserved: 0x0a8 ... 0x0f8 (21 个 u32) */

#define VIRTIO_MMIO_CONFIG_GENERATION 0x0fc
#define VIRTIO_MMIO_CONFIG 0x100

/* VirtIO MMIO Magic Number */
#define VIRTIO_MMIO_MAGIC 0x74726976

/* VirtIO Status Bits */
#define VIRTIO_STATUS_ACKNOWLEDGE 1
#define VIRTIO_STATUS_DRIVER 2
#define VIRTIO_STATUS_DRIVER_OK 4
#define VIRTIO_STATUS_FEATURES_OK 8
#define VIRTIO_STATUS_FAILED 128

/* VirtIO MMIO 设备结构 */
typedef struct virtio_mmio_device {
    volatile uint8_t *base; // MMIO 基地址
    uint32_t irq;           // 中断号
    uint32_t version;       // VirtIO 版本
    uint32_t device_id;     // 设备类型ID
} virtio_mmio_device_t;

static inline uint32_t virtio_mmio_read32(virtio_mmio_device_t *dev,
                                          uint32_t offset) {
    return *(volatile uint32_t *)(dev->base + offset);
}

static inline void virtio_mmio_write32(virtio_mmio_device_t *dev,
                                       uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(dev->base + offset) = value;
}

extern virtio_driver_op_t virtio_mmio_ops;
