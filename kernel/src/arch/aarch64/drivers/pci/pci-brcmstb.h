#pragma once

#include <libs/klibc.h>

/* MISC 寄存器 */
#define PCIE_MISC_MISC_CTRL 0x4008
#define PCIE_MISC_MISC_CTRL_SCB_ACCESS_EN (1 << 12)
#define PCIE_MISC_MISC_CTRL_CFG_READ_UR_MODE (1 << 13)
#define PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_MASK 0x300000
#define PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_128 0x0
#define PCIE_MISC_MISC_CTRL_BURST_ALIGN (1 << 1)

#define PCIE_MISC_RC_BAR1_CONFIG_LO 0x402c
#define PCIE_MISC_RC_BAR2_CONFIG_LO 0x4034
#define PCIE_MISC_RC_BAR2_CONFIG_HI 0x4038
#define PCIE_MISC_RC_BAR3_CONFIG_LO 0x403c

#define PCIE_MISC_PCIE_CTRL 0x4064
#define PCIE_MISC_PCIE_CTRL_PCIE_PERSTB (1 << 2)
#define PCIE_MISC_PCIE_CTRL_PCIE_L23_REQUEST (1 << 0)

#define PCIE_MISC_PCIE_STATUS 0x4068
#define PCIE_MISC_PCIE_STATUS_PCIE_PORT 0x80
#define PCIE_MISC_PCIE_STATUS_PCIE_DL_ACTIVE 0x20
#define PCIE_MISC_PCIE_STATUS_PCIE_PHYLINKUP 0x10
#define PCIE_MISC_PCIE_STATUS_PCIE_LINK_IN_L23 0x40

#define PCIE_MISC_REVISION 0x406c
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LO 0x400c
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_HI 0x4010
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT 0x4070
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI 0x4080
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI 0x4084
#define PCIE_MISC_HARD_PCIE_HARD_DEBUG 0x4204

/* RGR1 寄存器 */
#define PCIE_RGR1_SW_INIT_1 0x9210
#define PCIE_RGR1_SW_INIT_1_PERST (1 << 0)
#define PCIE_RGR1_SW_INIT_1_INIT (1 << 1)

/* RC 配置空间 */
#define PCIE_RC_CFG_VENDOR_ID 0x0000
#define PCIE_RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1 0x0188
#define PCIE_RC_CFG_PRIV1_ID_VAL3 0x043c

/* 配置空间访问 */
#define PCIE_EXT_CFG_INDEX 0x9000
#define PCIE_EXT_CFG_DATA 0x9004
#define PCIE_EXT_CFG_PCIE_EXT_CFG_DATA 0x8000

typedef struct {
    uint64_t pcie_base; // PCIe 配置寄存器基地址
    uint64_t pcie_size;
    uint64_t msi_base; // MSI 控制器基地址（如果有）
    uint64_t msi_size;
    bool found;
} pcie_brcmstb_config_t;

typedef struct {
    uint64_t pcie_base_phys;
    uint64_t pcie_base_virt;
    uint64_t pcie_size;

    uint64_t config_base_phys; // 配置空间基地址
    uint64_t config_base_virt;
    uint64_t config_size;

    bool initialized;
} pcie_brcmstb_context_t;

void pci_brcmstb_init();
