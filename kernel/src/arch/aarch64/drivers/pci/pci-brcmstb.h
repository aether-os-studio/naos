#pragma once

#include <libs/klibc.h>

typedef struct brcmstb_pcie {
    uint64_t ecam_base; // PCIe配置空间基地址
    uint64_t ecam_size;
    uint64_t rc_cfg_base; // RC配置寄存器基地址
    uint64_t rc_cfg_size;
    uint32_t msi_target_addr; // MSI目标地址
    uint16_t segment;
    uint8_t bus_start;
    uint8_t bus_end;
    bool initialized;
} brcmstb_pcie_t;

void pci_brcmstb_init();
