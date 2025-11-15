#pragma once

#include <libs/klibc.h>

#define PCIE_RC_CFG_VENDOR_ID 0x0000
#define PCIE_RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1 0x0188
#define VENDOR_SPECIFIC_REG1_ENDIAN_MODE_SHIFT 2
#define VENDOR_SPECIFIC_REG1_ENDIAN_MODE_MASK 0x0c

#define PCIE_RC_CFG_PRIV1_ID_VAL3 0x043c
#define PCIE_RC_CFG_PRIV1_LINK_CAPABILITY 0x04dc
#define PRIV1_LINK_CAPABILITY_L1_L0S_MASK 0x0c00

#define PCIE_MISC_MISC_CTRL 0x4008
#define PCIE_MISC_MISC_CTRL_SCB_ACCESS_EN (1 << 12)
#define PCIE_MISC_MISC_CTRL_CFG_READ_UR_MODE (1 << 13)
#define PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_SHIFT 20
#define PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_128 0x0
#define PCIE_MISC_MISC_CTRL_BURST_ALIGN (1 << 1)
#define PCIE_MISC_MISC_CTRL_SCB_SIZE_0_SHIFT 27

#define PCIE_MISC_RC_BAR1_CONFIG_LO 0x402c
#define PCIE_MISC_RC_BAR2_CONFIG_LO 0x4034
#define PCIE_MISC_RC_BAR2_CONFIG_HI 0x4038
#define PCIE_MISC_RC_BAR3_CONFIG_LO 0x403c
#define PCIE_MISC_RC_BAR_CONFIG_LO_SIZE_MASK 0x1f

#define PCIE_MISC_PCIE_CTRL 0x4064
#define PCIE_MISC_PCIE_CTRL_PCIE_PERSTB (1 << 2)

#define PCIE_MISC_PCIE_STATUS 0x4068
#define PCIE_MISC_PCIE_STATUS_RC_MODE (1 << 7)
#define PCIE_MISC_PCIE_STATUS_PCIE_DL_ACTIVE (1 << 5)
#define PCIE_MISC_PCIE_STATUS_PCIE_PHYLINKUP (1 << 4)

#define PCIE_MISC_REVISION 0x406c

#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LO 0x400c
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_HI 0x4010
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT 0x4070
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI 0x4080
#define PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI 0x4084

#define PCIE_MISC_HARD_PCIE_HARD_DEBUG 0x4204
#define PCIE_HARD_DEBUG_SERDES_IDDQ (1 << 27)
#define PCIE_HARD_DEBUG_CLKREQ_ENABLE (1 << 1)

#define PCIE_RGR1_SW_INIT_1 0x9210
#define PCIE_RGR1_SW_INIT_1_PERST (1 << 0)
#define PCIE_RGR1_SW_INIT_1_INIT (1 << 1)

#define PCIE_EXT_CFG_INDEX 0x9000
#define PCIE_EXT_CFG_DATA 0x9004

/* MDIO 寄存器 */
#define PCIE_RC_DL_MDIO_ADDR 0x1100
#define PCIE_RC_DL_MDIO_WR_DATA 0x1104
#define PCIE_RC_DL_MDIO_RD_DATA 0x1108
#define MDIO_PKT_CMD_SHIFT 20
#define MDIO_PKT_PORT_SHIFT 16
#define MDIO_PKT_REG_SHIFT 0
#define MDIO_DATA_DONE (1U << 31)
#define MDIO_DATA_MASK 0x7fffffff

/* Link Status 寄存器 (PCIe 配置空间) */
#define PCIE_RC_CFG_LINK_STATUS 0x00be

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
