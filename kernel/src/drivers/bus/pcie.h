#pragma once

#include <drivers/bus/pci.h>

// PCIe Capability 寄存器偏移
#define PCIE_CAP_PCIE_CAPS 0x02    // PCIe Capabilities
#define PCIE_CAP_DEV_CAPS 0x04     // Device Capabilities
#define PCIE_CAP_DEV_CTRL 0x08     // Device Control
#define PCIE_CAP_DEV_STATUS 0x0A   // Device Status
#define PCIE_CAP_LINK_CAPS 0x0C    // Link Capabilities
#define PCIE_CAP_LINK_CTRL 0x10    // Link Control
#define PCIE_CAP_LINK_STATUS 0x12  // Link Status
#define PCIE_CAP_LINK_CAPS2 0x2C   // Link Capabilities 2
#define PCIE_CAP_LINK_CTRL2 0x30   // Link Control 2 (PCIe 2.0+)
#define PCIE_CAP_LINK_STATUS2 0x32 // Link Status 2

// Link Capabilities bits
#define PCIE_LINK_CAP_MAX_SPEED_MASK 0x0F
#define PCIE_LINK_CAP_MAX_WIDTH_MASK 0x3F0
#define PCIE_LINK_CAP_MAX_WIDTH_SHIFT 4

// Link Control bits
#define PCIE_LINK_CTRL_RETRAIN (1 << 5)

// Link Status bits
#define PCIE_LINK_STATUS_SPEED_MASK 0x0F
#define PCIE_LINK_STATUS_WIDTH_MASK 0x3F0
#define PCIE_LINK_STATUS_WIDTH_SHIFT 4
#define PCIE_LINK_STATUS_TRAINING (1 << 11)

// PCIe 速度定义
#define PCIE_SPEED_2_5GT 1  // PCIe 1.0
#define PCIE_SPEED_5_0GT 2  // PCIe 2.0
#define PCIE_SPEED_8_0GT 3  // PCIe 3.0
#define PCIE_SPEED_16_0GT 4 // PCIe 4.0
#define PCIE_SPEED_32_0GT 5 // PCIe 5.0
#define PCIE_SPEED_64_0GT 6 // PCIe 6.0

// PCIe Capability ID
#define PCI_CAP_ID_PCIE 0x10

// 扩展 pci_device_t 结构
typedef struct pcie_info {
    uint8_t pcie_version;       // PCIe 版本
    uint8_t max_link_speed;     // 最大支持速度
    uint8_t current_link_speed; // 当前链路速度
    uint8_t max_link_width;     // 最大链路宽度
    uint8_t current_link_width; // 当前链路宽度
    uint8_t pcie_cap_offset;    // PCIe Capability 偏移
    bool is_pcie;               // 是否为 PCIe 设备
} pcie_info_t;

void pcie_optimize_link(pci_device_t *dev);
