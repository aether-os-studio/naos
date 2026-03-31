#include "mt7921.h"

static uint32_t mt7921_make_dma_prefetch(uint32_t cnt, uint32_t base) {
    return (cnt & 0xffU) | ((base & 0xffffU) << 16);
}

static uint32_t mt7921_make_group_quota(uint32_t min, uint32_t max) {
    return (min & 0x0fffU) | ((max & 0x0fffU) << 16);
}

static void mt7921_rmw_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t mask,
                           uint32_t val) {
    uint32_t cur = mt7921_read_reg(priv, addr);

    cur = (cur & ~mask) | (val & mask);
    mt7921_write_reg(priv, addr, cur);
}

static void mt7921_set_reg_bits(mt7921_priv_t *priv, uint32_t addr,
                                uint32_t bits) {
    mt7921_write_reg(priv, addr, mt7921_read_reg(priv, addr) | bits);
}

static void mt7921_clear_reg_bits(mt7921_priv_t *priv, uint32_t addr,
                                  uint32_t bits) {
    mt7921_write_reg(priv, addr, mt7921_read_reg(priv, addr) & ~bits);
}

static void mt7921_dma_prefetch(mt7921_priv_t *priv) {
    mt7921_rmw_reg(priv, MT_UWFDMA0_TX_RING_EXT_CTRL(0), 0xffff00ffU,
                   mt7921_make_dma_prefetch(4, 0x080));
    mt7921_rmw_reg(priv, MT_UWFDMA0_TX_RING_EXT_CTRL(1), 0xffff00ffU,
                   mt7921_make_dma_prefetch(4, 0x0c0));
    mt7921_rmw_reg(priv, MT_UWFDMA0_TX_RING_EXT_CTRL(2), 0xffff00ffU,
                   mt7921_make_dma_prefetch(4, 0x100));
    mt7921_rmw_reg(priv, MT_UWFDMA0_TX_RING_EXT_CTRL(3), 0xffff00ffU,
                   mt7921_make_dma_prefetch(4, 0x140));
    mt7921_rmw_reg(priv, MT_UWFDMA0_TX_RING_EXT_CTRL(4), 0xffff00ffU,
                   mt7921_make_dma_prefetch(4, 0x180));
    mt7921_rmw_reg(priv, MT_UWFDMA0_TX_RING_EXT_CTRL(16), 0xffff00ffU,
                   mt7921_make_dma_prefetch(4, 0x280));
    mt7921_rmw_reg(priv, MT_UWFDMA0_TX_RING_EXT_CTRL(17), 0xffff00ffU,
                   mt7921_make_dma_prefetch(4, 0x2c0));
}

static void mt7921_wfdma_init(mt7921_priv_t *priv) {
    int i;

    mt7921_dma_prefetch(priv);

    mt7921_clear_reg_bits(priv, MT_UWFDMA0_GLO_CFG,
                          MT_WFDMA0_GLO_CFG_OMIT_RX_INFO);
    mt7921_set_reg_bits(
        priv, MT_UWFDMA0_GLO_CFG,
        MT_WFDMA0_GLO_CFG_OMIT_TX_INFO | MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2 |
            MT_WFDMA0_GLO_CFG_FW_DWLD_BYPASS_DMASHDL |
            MT_WFDMA0_GLO_CFG_TX_DMA_EN | MT_WFDMA0_GLO_CFG_RX_DMA_EN);

    mt7921_rmw_reg(priv, MT_DMASHDL_REFILL, MT_DMASHDL_REFILL_MASK,
                   0xffe00000U);
    mt7921_clear_reg_bits(priv, MT_DMASHDL_PAGE, MT_DMASHDL_GROUP_SEQ_ORDER);
    mt7921_rmw_reg(priv, MT_DMASHDL_PKT_MAX_SIZE,
                   MT_DMASHDL_PKT_MAX_SIZE_PLE_MASK |
                       MT_DMASHDL_PKT_MAX_SIZE_PSE_MASK,
                   1U);

    for (i = 0; i < 5; i++) {
        mt7921_write_reg(priv, MT_DMASHDL_GROUP_QUOTA(i),
                         mt7921_make_group_quota(0x3, 0xfff));
    }

    for (i = 5; i < 16; i++) {
        mt7921_write_reg(priv, MT_DMASHDL_GROUP_QUOTA(i),
                         mt7921_make_group_quota(0x0, 0x0));
    }

    mt7921_write_reg(priv, MT_DMASHDL_Q_MAP(0), 0x32013201U);
    mt7921_write_reg(priv, MT_DMASHDL_Q_MAP(1), 0x32013201U);
    mt7921_write_reg(priv, MT_DMASHDL_Q_MAP(2), 0x55555444U);
    mt7921_write_reg(priv, MT_DMASHDL_Q_MAP(3), 0x55555444U);
    mt7921_write_reg(priv, MT_DMASHDL_SCHED_SET(0), 0x76540132U);
    mt7921_write_reg(priv, MT_DMASHDL_SCHED_SET(1), 0xfedcba98U);

    mt7921_set_reg_bits(priv, MT_WFDMA_DUMMY_CR, MT_WFDMA_NEED_REINIT);
}

static int mt7921_dma_rx_evt_ep4(mt7921_priv_t *priv) {
    if (!mt7921_wait_reg_mask(priv, MT_UWFDMA0_GLO_CFG,
                              MT_WFDMA0_GLO_CFG_RX_DMA_BUSY, 0, 1000, 1)) {
        return -ETIMEDOUT;
    }

    mt7921_clear_reg_bits(priv, MT_UWFDMA0_GLO_CFG,
                          MT_WFDMA0_GLO_CFG_RX_DMA_EN);
    mt7921_set_reg_bits(priv, MT_WFDMA_HOST_CONFIG,
                        MT_WFDMA_HOST_CONFIG_USB_RXEVT_EP4_EN);
    mt7921_set_reg_bits(priv, MT_UWFDMA0_GLO_CFG, MT_WFDMA0_GLO_CFG_RX_DMA_EN);

    return 0;
}

static void mt7921_epctl_rst_opt(mt7921_priv_t *priv, bool reset) {
    uint32_t val = mt7921_read_uhw_reg(priv, MT_SSUSB_EPCTL_CSR_EP_RST_OPT);

    if (reset) {
        val |= MT_SSUSB_EPCTL_RST_OPT_MASK;
    } else {
        val &= ~MT_SSUSB_EPCTL_RST_OPT_MASK;
    }

    mt7921_write_uhw_reg(priv, MT_SSUSB_EPCTL_CSR_EP_RST_OPT, val);
}

int mt7921_mcu_power_on(mt7921_priv_t *priv) {
    int ret;

    ret = mt7921_vendor_request(priv, MT_VEND_POWER_ON,
                                USB_DIR_OUT | MT_USB_TYPE_VENDOR, 0, 0x1, NULL,
                                0);
    if (ret) {
        return ret;
    }

    if (!mt7921_wait_reg_mask(priv, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_PWR_ON,
                              MT_TOP_MISC2_FW_PWR_ON, 500, 1000)) {
        printk("mt7921: timed out powering on MCU\n");
        return -ETIMEDOUT;
    }

    return 0;
}

int mt7921_dma_init(mt7921_priv_t *priv, bool resume) {
    int err;

    mt7921_wfdma_init(priv);

    mt7921_clear_reg_bits(priv, MT_UDMA_WLCFG_0, MT_WL_RX_FLUSH);
    mt7921_set_reg_bits(priv, MT_UDMA_WLCFG_0,
                        MT_WL_RX_EN | MT_WL_TX_EN | MT_WL_RX_MPSZ_PAD0 |
                            MT_TICK_1US_EN);
    mt7921_clear_reg_bits(priv, MT_UDMA_WLCFG_0,
                          MT_WL_RX_AGG_TO_MASK | MT_WL_RX_AGG_LMT_MASK);
    mt7921_clear_reg_bits(priv, MT_UDMA_WLCFG_1, MT_WL_RX_AGG_PKT_LMT_MASK);

    if (resume) {
        return 0;
    }

    err = mt7921_dma_rx_evt_ep4(priv);
    if (err) {
        return err;
    }

    mt7921_epctl_rst_opt(priv, false);
    return 0;
}

int mt7921_wfsys_reset(mt7921_priv_t *priv) {
    uint32_t val;
    int i;

    mt7921_epctl_rst_opt(priv, false);

    val = mt7921_read_uhw_reg(priv, MT_CBTOP_RGU_WF_SUBSYS_RST);
    val |= MT_CBTOP_RGU_WF_SUBSYS_RST_WF_WHOLE_PATH;
    mt7921_write_uhw_reg(priv, MT_CBTOP_RGU_WF_SUBSYS_RST, val);

    mt7921_delay_us(20);

    val = mt7921_read_uhw_reg(priv, MT_CBTOP_RGU_WF_SUBSYS_RST);
    val &= ~MT_CBTOP_RGU_WF_SUBSYS_RST_WF_WHOLE_PATH;
    mt7921_write_uhw_reg(priv, MT_CBTOP_RGU_WF_SUBSYS_RST, val);
    mt7921_write_uhw_reg(priv, MT_UDMA_CONN_INFRA_STATUS_SEL, 0);

    for (i = 0; i < 2; i++) {
        val = mt7921_read_uhw_reg(priv, MT_UDMA_CONN_INFRA_STATUS);
        if ((val & MT_UDMA_CONN_WFSYS_INIT_DONE) ==
            MT_UDMA_CONN_WFSYS_INIT_DONE) {
            return 0;
        }

        mt7921_delay_ms(100);
    }

    printk("mt7921: timed out waiting WFSYS init done\n");
    return -ETIMEDOUT;
}
