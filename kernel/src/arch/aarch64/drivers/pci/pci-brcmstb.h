#pragma once

#include <libs/klibc.h>

#define PCIE_LNKSTA 0x00be
#define PCIE_HW_REV 0x406c
#define PCIE_BRIDGE_CTL 0x9210
#define PCIE_BRIDGE_STATE 0x4068
#define PCIE_HARD_DEBUG 0x4204
#define PCIE_MISC_CTRL 0x4008

#define PCIE_RC_BAR1_LO 0x402c
#define PCIE_RC_BAR2_LO 0x4034
#define PCIE_RC_BAR2_HI 0x4038
#define PCIE_RC_BAR3_LO 0x403c

#define PCIE_VENDOR_REG1 0x0188
#define PCIE_PRIV1_ID_VAL3 0x043c
#define PCIE_PRIV1_LINK_CAP 0x04dc

#define PCIE_CFG_INDEX 0x9000
#define PCIE_CFG_DATA 0x8000

#define PCIE_MDIO_ADDR 0x1100
#define PCIE_MDIO_WR_DATA 0x1104
#define PCIE_MDIO_RD_DATA 0x1108

// Outbound window registers (window N)
#define PCIE_OUTBOUND_WIN_PCIE_LO(n) (0x400c + (n) * 8)
#define PCIE_OUTBOUND_WIN_PCIE_HI(n) (0x4010 + (n) * 8)
#define PCIE_OUTBOUND_WIN_BASE_LIMIT(n) (0x4070 + (n) * 4)
#define PCIE_OUTBOUND_WIN_BASE_HI(n) (0x4080 + (n) * 8)
#define PCIE_OUTBOUND_WIN_LIMIT_HI(n) (0x4084 + (n) * 8)

// lnksta (0x00be)
#define LNKSTA_LINK_SPEED_SHIFT 0
#define LNKSTA_LINK_SPEED_MASK 0xF
#define LNKSTA_LINK_WIDTH_SHIFT 4
#define LNKSTA_LINK_WIDTH_MASK 0x3F

// bridgeCtl (0x9210)
#define BRIDGE_CTL_RESET (1 << 0)
#define BRIDGE_CTL_SW_INIT (1 << 1)

// bridgeState (0x4068)
#define BRIDGE_STATE_PHY_ACTIVE (1 << 4)
#define BRIDGE_STATE_DL_ACTIVE (1 << 5)
#define BRIDGE_STATE_RC_MODE (1 << 7)

// hardDebug (0x4204)
#define HARD_DEBUG_CLKREQ_ENABLE (1 << 1)
#define HARD_DEBUG_SERDES_DISABLE (1 << 27)

// miscCtl (0x4008)
#define MISC_CTRL_ACCESS_ENABLE (1 << 12)
#define MISC_CTRL_READ_UR_MODE (1 << 13)
#define MISC_CTRL_MAX_BURST_SHIFT 20
#define MISC_CTRL_MAX_BURST_MASK (0x3 << 20)
#define MISC_CTRL_SCB_SIZE_0_SHIFT 27
#define MISC_CTRL_SCB_SIZE_0_MASK (0x1F << 27)

// vendorReg1 (0x0188)
#define VENDOR_REG1_ENDIAN_MODE_SHIFT 2
#define VENDOR_REG1_ENDIAN_MODE_MASK (0x3 << 2)

// priv1 (0x043c, 0x04dc)
#define PRIV1_ID_MASK 0xFFFFFF
#define PRIV1_LINK_CAP_SHIFT 10
#define PRIV1_LINK_CAP_MASK (0x3 << 10)

// cfgIndex (0x9000)
#define CFG_INDEX_BUS_SHIFT 20
#define CFG_INDEX_BUS_MASK (0xFF << 20)
#define CFG_INDEX_SLOT_SHIFT 15
#define CFG_INDEX_SLOT_MASK (0x1F << 15)
#define CFG_INDEX_FUNC_SHIFT 12
#define CFG_INDEX_FUNC_MASK (0x7 << 12)

// MDIO
#define MDIO_PKT_CMD_SHIFT 20
#define MDIO_PKT_CMD_MASK (0xFFF << 20)
#define MDIO_PKT_PORT_SHIFT 16
#define MDIO_PKT_PORT_MASK (0xF << 16)
#define MDIO_PKT_REG_SHIFT 0
#define MDIO_PKT_REG_MASK 0xFFFF
#define MDIO_DATA_DONE (1u << 31)
#define MDIO_DATA_MASK 0x7FFFFFFF

// RC BAR
#define RC_BAR_SIZE_MASK 0x1F

typedef struct {
    uint32_t flags;
    uint64_t pci_addr;
    uint64_t cpu_addr;
    uint64_t size;
} pcie_range_t;

typedef struct {
    uint64_t pcie_base_phys;
    uint64_t pcie_base_virt;
    uint64_t pcie_size;
    uint8_t bus_start;
    uint8_t bus_end;
    int fdt_node;
    bool initialized;

    uint64_t mem_pci_base;
    uint64_t mem_cpu_base;
    uint64_t mem_size;
    uint64_t mem_current;
} pcie_brcmstb_context_t;

void pci_brcmstb_init(void);
