#include <drivers/bus/pcie.h>
#include <drivers/kernel_logger.h>
#include <mm/mm.h>

// 获取 PCIe 版本字符串
static const char *pcie_speed_to_string(uint8_t speed) {
    switch (speed) {
    case PCIE_SPEED_2_5GT:
        return "2.5 GT/s (Gen 1)";
    case PCIE_SPEED_5_0GT:
        return "5.0 GT/s (Gen 2)";
    case PCIE_SPEED_8_0GT:
        return "8.0 GT/s (Gen 3)";
    case PCIE_SPEED_16_0GT:
        return "16.0 GT/s (Gen 4)";
    case PCIE_SPEED_32_0GT:
        return "32.0 GT/s (Gen 5)";
    case PCIE_SPEED_64_0GT:
        return "64.0 GT/s (Gen 6)";
    default:
        return "Unknown";
    }
}

// 检测设备的 PCIe 信息
bool pci_detect_pcie_info(pci_device_t *dev, pcie_info_t *info) {
    memset(info, 0, sizeof(pcie_info_t));

    // 查找 PCIe Capability
    uint8_t cap_offset = pci_enumerate_capability_list(dev, PCI_CAP_ID_PCIE);
    if (!cap_offset) {
        info->is_pcie = false;
        return false;
    }

    info->is_pcie = true;
    info->pcie_cap_offset = cap_offset;

    // 读取 PCIe Capabilities 寄存器
    uint16_t pcie_caps =
        dev->op->read16(dev->bus, dev->slot, dev->func, dev->segment,
                        cap_offset + PCIE_CAP_PCIE_CAPS);
    info->pcie_version = pcie_caps & 0xF;

    // 读取 Link Capabilities
    uint32_t link_caps =
        dev->op->read32(dev->bus, dev->slot, dev->func, dev->segment,
                        cap_offset + PCIE_CAP_LINK_CAPS);
    info->max_link_speed = link_caps & PCIE_LINK_CAP_MAX_SPEED_MASK;
    info->max_link_width = (link_caps & PCIE_LINK_CAP_MAX_WIDTH_MASK) >>
                           PCIE_LINK_CAP_MAX_WIDTH_SHIFT;

    // 读取 Link Status
    uint16_t link_status =
        dev->op->read16(dev->bus, dev->slot, dev->func, dev->segment,
                        cap_offset + PCIE_CAP_LINK_STATUS);
    info->current_link_speed = link_status & PCIE_LINK_STATUS_SPEED_MASK;
    info->current_link_width = (link_status & PCIE_LINK_STATUS_WIDTH_MASK) >>
                               PCIE_LINK_STATUS_WIDTH_SHIFT;

    return true;
}

// 等待链路训练完成
static bool pci_wait_for_link_training(pci_device_t *dev, uint8_t cap_offset,
                                       uint32_t timeout_ms) {
    uint64_t timeout_ns = nano_time() + (uint64_t)timeout_ms * 1000000;

    while (nano_time() < timeout_ns) {
        uint16_t link_status =
            dev->op->read16(dev->bus, dev->slot, dev->func, dev->segment,
                            cap_offset + PCIE_CAP_LINK_STATUS);
        if (!(link_status & PCIE_LINK_STATUS_TRAINING)) {
            return true; // 训练完成
        }
    }

    return false; // 超时
}

// 重训练链路
static bool pci_retrain_link(pci_device_t *dev, uint8_t cap_offset) {
    // 读取 Link Control
    uint16_t link_ctrl =
        dev->op->read16(dev->bus, dev->slot, dev->func, dev->segment,
                        cap_offset + PCIE_CAP_LINK_CTRL);

    // 设置 Retrain Link 位
    link_ctrl |= PCIE_LINK_CTRL_RETRAIN;
    dev->op->write16(dev->bus, dev->slot, dev->func, dev->segment,
                     cap_offset + PCIE_CAP_LINK_CTRL, link_ctrl);

    // 等待训练完成 (100ms 超时)
    return pci_wait_for_link_training(dev, cap_offset, 100);
}

// 设置目标链路速度
bool pci_set_link_speed(pci_device_t *dev, pcie_info_t *info,
                        uint8_t target_speed) {
    if (!info->is_pcie) {
        return false;
    }

    if (target_speed > info->max_link_speed) {
        printk("PCIe device target speed Gen%d exceeds max supported Gen%d\n",
               target_speed, info->max_link_speed);
        return false;
    }

    uint8_t cap_offset = info->pcie_cap_offset;

    // 检查是否支持 Link Control 2 (PCIe 2.0+)
    if (info->pcie_version >= 2 && target_speed >= PCIE_SPEED_5_0GT) {
        // 读取 Link Control 2
        uint16_t link_ctrl2 =
            dev->op->read16(dev->bus, dev->slot, dev->func, dev->segment,
                            cap_offset + PCIE_CAP_LINK_CTRL2);

        // 设置目标链路速度
        link_ctrl2 = (link_ctrl2 & ~0xF) | target_speed;
        dev->op->write16(dev->bus, dev->slot, dev->func, dev->segment,
                         cap_offset + PCIE_CAP_LINK_CTRL2, link_ctrl2);

        printk("PCIe device set target link speed to %s\n",
               pcie_speed_to_string(target_speed));

        // 重训练链路
        if (!pci_retrain_link(dev, cap_offset)) {
            printk("PCIe device link retraining timeout\n");
            return false;
        }

        // 验证结果
        uint16_t link_status =
            dev->op->read16(dev->bus, dev->slot, dev->func, dev->segment,
                            cap_offset + PCIE_CAP_LINK_STATUS);
        uint8_t new_speed = link_status & PCIE_LINK_STATUS_SPEED_MASK;

        if (new_speed == target_speed) {
            info->current_link_speed = new_speed;
            printk("PCIe device successfully negotiated to %s\n",
                   pcie_speed_to_string(new_speed));
            return true;
        } else {
            printk("PCIe device link speed negotiation failed, current: %s, "
                   "target: %s\n",
                   pcie_speed_to_string(new_speed),
                   pcie_speed_to_string(target_speed));
            return false;
        }
    }

    return false;
}

// 配置 PCIe 3.0+ 均衡（如果需要）
static void pci_configure_gen3_equalization(pci_device_t *dev,
                                            pcie_info_t *info) {
    if (info->pcie_version < 3 || info->max_link_speed < PCIE_SPEED_8_0GT) {
        return;
    }

    uint8_t cap_offset = info->pcie_cap_offset;

    // 读取 Device Capabilities 2
    uint32_t dev_caps2 = dev->op->read32(dev->bus, dev->slot, dev->func,
                                         dev->segment, cap_offset + 0x24);

    // 检查是否支持链路均衡
    if (dev_caps2 & (1 << 0)) {
        printk("PCIe device supports Gen3 Link Equalization\n");
    }
}

void pcie_optimize_link(pci_device_t *dev) {
    pcie_info_t *info = malloc(sizeof(pcie_info_t));
    memset(info, 0, sizeof(pcie_info_t));

    if (!pci_detect_pcie_info(dev, info)) {
        // 不是 PCIe 设备，跑路
        return;
    }

    printk("PCIe device version: %d.x\n", info->pcie_version);
    printk("PCIe device max link speed: %s\n",
           pcie_speed_to_string(info->max_link_speed));

    // 检查是否需要升级链路速度
    if (info->current_link_speed < info->max_link_speed) {
        printk("PCIe device link is not running at maximum speed, attempting "
               "upgrade...\n");

        // 配置 Gen3+ 均衡
        if (info->max_link_speed >= PCIE_SPEED_8_0GT) {
            pci_configure_gen3_equalization(dev, info);
        }

        // 尝试升级到最高速度
        if (pci_set_link_speed(dev, info, info->max_link_speed)) {
            printk("PCIe device link speed upgrade successful!\n");
        } else {
            printk("PCIe device link speed upgrade failed, staying at current "
                   "speed\n");
        }
    } else {
        printk("PCIe device link is already at maximum speed\n");
    }

    dev->pcie = info;
}
