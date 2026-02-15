#pragma once

#include <libs/klibc.h>
#include <libs/aether/stdio.h>
#include <libs/mutex.h>
#include <libs/aether/usb.h>

typedef struct mt7921_priv {
    struct usbdevice_s *usbdev;
    mutex_t reg_lock;
    uint8_t macaddr[6];
    uint8_t antenna_mask;
    bool has_2ghz;
    bool has_5ghz;
    bool has_6ghz;
} mt7921_priv_t;

#define MT_USB_TYPE_UHW_VENDOR (USB_TYPE_VENDOR | 0x1e)

uint32_t mt7921_read_uhw_reg(mt7921_priv_t *priv, uint32_t addr);
void mt7921_write_uhw_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t val);

uint32_t mt7921_read_reg(mt7921_priv_t *priv, uint32_t addr);
void mt7921_write_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t val);

#define MT_TOP_MISC2_FW_N9_RDY_SHIFT 0
#define MT_TOP_MISC2_FW_N9_RDY_MASK (1 << 0)

#define mt76_get_field(dev, reg, field)                                        \
    ((mt7921_read_reg(dev, reg) & (field##_MASK)) >> (field##_SHIFT))

int mt7921_wfsys_reset(mt7921_priv_t *priv);
int mt76u_vendor_request(mt7921_priv_t *dev, uint8_t req, uint8_t req_type,
                         uint16_t val, uint16_t offset, void *buf, size_t len);
bool mt7921_wait(mt7921_priv_t *priv, uint32_t addr, uint32_t mask,
                 uint32_t val, uint64_t timeout_ms, uint64_t tick);

// mediatek vendor requests
#define MT_VEND_DEV_MODE 0x1
#define MT_VEND_WRITE 0x2
#define MT_VEND_POWER_ON 0x4
#define MT_VEND_MULTI_WRITE 0x6
#define MT_VEND_MULTI_READ 0x7
#define MT_VEND_READ_EEPROM 0x9
#define MT_VEND_WRITE_FCE 0x42
#define MT_VEND_WRITE_CFG 0x46
#define MT_VEND_READ_CFG 0x47
#define MT_VEND_READ_EXT 0x63
#define MT_VEND_WRITE_EXT 0x66

#define MT_UWFDMA0_BASE 0x7c024000U
#define MT_UWFDMA0_GLO_CFG (MT_UWFDMA0_BASE + 0x208U)
#define MT_UWFDMA0_TX_RING_EXT_CTRL(idx)                                       \
    (MT_UWFDMA0_BASE + 0x600U + ((uint32_t)(idx) << 2))

#define MT_DMA_SHDL_BASE 0x7c026000U
#define MT_DMASHDL_PAGE (MT_DMA_SHDL_BASE + 0x00cU)
#define MT_DMASHDL_REFILL (MT_DMA_SHDL_BASE + 0x010U)
#define MT_DMASHDL_PKT_MAX_SIZE (MT_DMA_SHDL_BASE + 0x01cU)
#define MT_DMASHDL_GROUP_QUOTA(idx)                                            \
    (MT_DMA_SHDL_BASE + 0x020U + ((uint32_t)(idx) << 2))
#define MT_DMASHDL_Q_MAP(idx)                                                  \
    (MT_DMA_SHDL_BASE + 0x060U + ((uint32_t)(idx) << 2))
#define MT_DMASHDL_SCHED_SET(idx)                                              \
    (MT_DMA_SHDL_BASE + 0x070U + ((uint32_t)(idx) << 2))

#define MT_WFDMA_DUMMY_CR 0x54000120U
#define MT_UDMA_TX_QSEL 0x74000008U
#define MT_UDMA_WLCFG_0 0x74000018U
#define MT_UDMA_WLCFG_1 0x7400000cU
#define MT_WFDMA_HOST_CONFIG 0x7c027030U
#define MT_SSUSB_EPCTL_CSR_EP_RST_OPT 0x74011890U
#define MT_CONN_ON_MISC 0x7c0600f0U

#define MT_FW_DL_EN (1U << 3)
#define MT_WFDMA0_GLO_CFG_TX_DMA_EN (1U << 0)
#define MT_WFDMA0_GLO_CFG_RX_DMA_EN (1U << 2)
#define MT_WFDMA0_GLO_CFG_RX_DMA_BUSY (1U << 3)
#define MT_WFDMA0_GLO_CFG_FW_DWLD_BYPASS_DMASHDL (1U << 9)
#define MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2 (1U << 21)
#define MT_WFDMA0_GLO_CFG_OMIT_RX_INFO (1U << 27)
#define MT_WFDMA0_GLO_CFG_OMIT_TX_INFO (1U << 28)

#define MT_WFDMA_NEED_REINIT (1U << 1)
#define MT_WFDMA_HOST_CONFIG_USB_RXEVT_EP4_EN (1U << 6)
#define MT_SSUSB_EPCTL_RST_OPT_MASK 0x007003f0U

#define MT_DMASHDL_REFILL_MASK 0xffff0000U
#define MT_DMASHDL_GROUP_SEQ_ORDER (1U << 16)
#define MT_DMASHDL_PKT_MAX_SIZE_PLE_MASK 0x00000fffU
#define MT_DMASHDL_PKT_MAX_SIZE_PSE_MASK 0x0fff0000U

#define MT_WL_RX_AGG_TO_MASK 0x000000ffU
#define MT_WL_RX_AGG_LMT_MASK 0x0000ff00U
#define MT_WL_RX_AGG_PKT_LMT_MASK 0x000000ffU
#define MT_WL_RX_MPSZ_PAD0 (1U << 18)
#define MT_WL_RX_FLUSH (1U << 19)
#define MT_TICK_1US_EN (1U << 20)
#define MT_WL_RX_EN (1U << 22)
#define MT_WL_TX_EN (1U << 23)

#define MT_TOP_MISC2_FW_N9_RDY_VALUE 0x3U
