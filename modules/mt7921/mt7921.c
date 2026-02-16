#include "mt7921.h"
#include <net/netdev.h>
#include <net/rtnl.h>

static void delay_us(uint64_t us) {
    uint64_t start = nano_time();
    while ((nano_time() - start) < us * 1000ULL) {
        asm volatile("nop");
    }
}

static void mt7921_rmw_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t mask,
                           uint32_t val) {
    uint32_t cur = mt7921_read_reg(priv, addr);
    cur = (cur & ~mask) | (val & mask);
    mt7921_write_reg(priv, addr, cur);
}

static void mt7921_set_reg_bits(mt7921_priv_t *priv, uint32_t addr,
                                uint32_t bits) {
    uint32_t cur = mt7921_read_reg(priv, addr);
    mt7921_write_reg(priv, addr, cur | bits);
}

static void mt7921_clear_reg_bits(mt7921_priv_t *priv, uint32_t addr,
                                  uint32_t bits) {
    uint32_t cur = mt7921_read_reg(priv, addr);
    mt7921_write_reg(priv, addr, cur & ~bits);
}

static uint32_t mt7921_make_dma_prefetch(uint32_t cnt, uint32_t base) {
    return (cnt & 0xffU) | ((base & 0xffffU) << 16);
}

static uint32_t mt7921_make_group_quota(uint32_t min, uint32_t max) {
    return (min & 0x0fffU) | ((max & 0x0fffU) << 16);
}

static bool mt7921_wait_mask_clear(mt7921_priv_t *priv, uint32_t addr,
                                   uint32_t mask, uint32_t timeout_us) {
    uint32_t i;

    for (i = 0; i < timeout_us; i++) {
        if ((mt7921_read_reg(priv, addr) & mask) == 0) {
            return true;
        }
        delay_us(1);
    }

    return false;
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

void mt7921_wfdma_init(mt7921_priv_t *priv) {
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
    if (!mt7921_wait_mask_clear(priv, MT_UWFDMA0_GLO_CFG,
                                MT_WFDMA0_GLO_CFG_RX_DMA_BUSY, 1000)) {
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

static int mt7921_dma_init(mt7921_priv_t *priv, bool resume) {
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

#define MT7921_FIRMWARE_WM "mediatek/WIFI_RAM_CODE_MT7961_1.bin"
#define MT7921_ROM_PATCH "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin"
#define MT7921_PATCH_SEC_TYPE_MASK 0x0000ffffU
#define MT7921_PATCH_SEC_TYPE_INFO 0x2U
#define MT7921_FW_FEATURE_NON_DL (1U << 6)
#define MT7921_VENDOR_COPY_CHUNK 2048U
#define MT7921_MCU_SCATTER_CHUNK 4096U

#define MT7921_MCU_CMD_FIELD_ID_MASK 0x000000ffU
#define MT7921_MCU_CMD_FIELD_EXT_ID_MASK 0x0000ff00U
#define MT7921_MCU_CMD_FIELD_QUERY (1U << 16)
#define MT7921_MCU_CMD_FIELD_CE (1U << 18)

#define MT7921_MCU_CMD(id) ((uint32_t)(id) & MT7921_MCU_CMD_FIELD_ID_MASK)
#define MT7921_MCU_CE_CMD(id) (MT7921_MCU_CMD_FIELD_CE | MT7921_MCU_CMD(id))
#define MT7921_MCU_EXT_CMD(id)                                                 \
    (MT7921_MCU_CMD(0xed) |                                                    \
     (((uint32_t)(id) << 8) & MT7921_MCU_CMD_FIELD_EXT_ID_MASK))

#define MT7921_MCU_CMD_TARGET_ADDRESS_LEN_REQ MT7921_MCU_CMD(0x01)
#define MT7921_MCU_CMD_FW_START_REQ MT7921_MCU_CMD(0x02)
#define MT7921_MCU_CMD_PATCH_START_REQ MT7921_MCU_CMD(0x05)
#define MT7921_MCU_CMD_PATCH_FINISH_REQ MT7921_MCU_CMD(0x07)
#define MT7921_MCU_CMD_PATCH_SEM_CONTROL MT7921_MCU_CMD(0x10)
#define MT7921_MCU_CMD_FW_SCATTER MT7921_MCU_CMD(0xee)

#define MT7921_MCU_CE_CMD_GET_NIC_CAPAB MT7921_MCU_CE_CMD(0x8a)
#define MT7921_MCU_CE_CMD_FWLOG_2_HOST MT7921_MCU_CE_CMD(0xc5)
#define MT7921_MCU_CE_CMD_START_HW_SCAN MT7921_MCU_CE_CMD(0x03)
#define MT7921_MCU_CE_CMD_SET_CHAN_DOMAIN MT7921_MCU_CE_CMD(0x0f)
#define MT7921_MCU_CE_CMD_SET_RX_FILTER MT7921_MCU_CE_CMD(0x0a)
#define MT7921_MCU_CE_CMD_CANCEL_HW_SCAN MT7921_MCU_CE_CMD(0x1b)

#define MT7921_MCU_EXT_CMD_MAC_INIT_CTRL MT7921_MCU_EXT_CMD(0x46)
#define MT7921_MCU_EXT_CMD_SET_RX_PATH MT7921_MCU_EXT_CMD(0x4e)
#define MT7921_MCU_EXT_CMD_EFUSE_BUFFER_MODE MT7921_MCU_EXT_CMD(0x21)

#define MT7921_PATCH_SEM_RELEASE 0
#define MT7921_PATCH_SEM_GET 1
#define MT7921_PATCH_NOT_DL_SEM_FAIL 0
#define MT7921_PATCH_IS_DL 1
#define MT7921_PATCH_NOT_DL_SEM_SUCCESS 2
#define MT7921_PATCH_REL_SEM_SUCCESS 3

#define MT7921_FW_FEATURE_SET_ENCRYPT (1U << 0)
#define MT7921_FW_FEATURE_SET_KEY_IDX_MASK 0x06U
#define MT7921_FW_FEATURE_SET_KEY_IDX_SHIFT 1
#define MT7921_FW_FEATURE_ENCRY_MODE (1U << 4)
#define MT7921_FW_FEATURE_OVERRIDE_ADDR (1U << 5)

#define MT7921_DL_MODE_ENCRYPT (1U << 0)
#define MT7921_DL_MODE_KEY_IDX_MASK 0x06U
#define MT7921_DL_MODE_KEY_IDX_SHIFT 1
#define MT7921_DL_MODE_RESET_SEC_IV (1U << 3)
#define MT7921_DL_MODE_NEED_RSP (1U << 31)
#define MT7921_DL_CONFIG_ENCRY_MODE_SEL (1U << 6)

#define MT7921_FW_START_OVERRIDE (1U << 0)
#define MT7921_PATCH_SEC_ENC_TYPE_MASK 0xff000000U
#define MT7921_PATCH_SEC_ENC_TYPE_SHIFT 24
#define MT7921_PATCH_SEC_ENC_TYPE_PLAIN 0x00U
#define MT7921_PATCH_SEC_ENC_TYPE_AES 0x01U
#define MT7921_PATCH_SEC_ENC_TYPE_SCRAMBLE 0x02U
#define MT7921_PATCH_SEC_ENC_AES_KEY_MASK 0x000000ffU

#define MT7921_PATCH_ADDRESS 0x200000U
#define MT7921_RAM_START_ADDRESS 0x900000U
#define MT7921_NIC_CAP_BUF_SIZE 1024
#define MT7921_MCU_RX_BUF_SIZE 2048

#define MT7921_SDIO_HDR_TX_BYTES_MASK 0x0000ffffU
#define MT7921_SDIO_HDR_PKT_TYPE_SHIFT 16
#define MT7921_SDIO_HDR_PKT_TYPE_CMD 0U
#define MT7921_SDIO_HDR_SIZE 4U
#define MT7921_USB_BULK_BUF_SIZE 4096U
#define MT7921_TXWI_SIZE 64U

#define MT7921_TX_TYPE_SF 1U
#define MT7921_LMAC_AC00 0U
#define MT7921_LMAC_AC01 1U
#define MT7921_LMAC_AC02 2U
#define MT7921_LMAC_AC03 3U
#define MT7921_HDR_FORMAT_80211 2U

#define MT7921_TXD0_Q_IDX_SHIFT 25
#define MT7921_TXD0_PKT_FMT_SHIFT 23
#define MT7921_TXD0_TX_BYTES_MASK 0x0000ffffU

#define MT7921_TXD1_LONG_FORMAT (1U << 31)
#define MT7921_TXD1_OWN_MAC_SHIFT 24
#define MT7921_TXD1_TID_SHIFT 20
#define MT7921_TXD1_HDR_FORMAT_SHIFT 16
#define MT7921_TXD1_HDR_INFO_SHIFT 11
#define MT7921_TXD1_WLAN_IDX_MASK 0x000003ffU

#define MT7921_TXD2_MULTICAST (1U << 10)
#define MT7921_TXD2_FIX_RATE (1U << 31)
#define MT7921_TXD2_FRAME_TYPE_SHIFT 4
#define MT7921_TXD2_SUB_TYPE_SHIFT 0

#define MT7921_TXD3_REM_TX_COUNT_SHIFT 11

#define MT7921_TXD8_L_TYPE_SHIFT 4
#define MT7921_TXD8_L_SUB_TYPE_SHIFT 0

#define MT7921_RXD0_PKT_FLAG_SHIFT 16
#define MT7921_RXD0_PKT_FLAG_MASK 0x000f0000U
#define MT7921_RXD0_PKT_TYPE_SHIFT 27
#define MT7921_RXD0_PKT_TYPE_MASK 0xf8000000U
#define MT7921_RXD0_LENGTH_MASK 0x0000ffffU

#define MT7921_RXD1_GROUP_1 (1U << 11)
#define MT7921_RXD1_GROUP_2 (1U << 12)
#define MT7921_RXD1_GROUP_3 (1U << 13)
#define MT7921_RXD1_GROUP_4 (1U << 14)
#define MT7921_RXD1_GROUP_5 (1U << 15)

#define MT7921_RXD2_HDR_OFFSET_SHIFT 14
#define MT7921_RXD2_HDR_OFFSET_MASK 0x0000c000U

#define MT7921_PKT_TYPE_NORMAL 2U
#define MT7921_PKT_TYPE_RX_EVENT 7U
#define MT7921_PKT_TYPE_NORMAL_MCU 8U

#define MT7921_NIC_CAP_MAC_ADDR 7
#define MT7921_NIC_CAP_PHY 8
#define MT7921_NIC_CAP_6G 0x18

#define MT7921_HW_PATH_2G_BIT (1U << 0)
#define MT7921_HW_PATH_5G_BIT (1U << 1)

#define MT7921_SCAN_FUNC_RANDOM_MAC (1U << 0)
#define MT7921_SCAN_FUNC_SPLIT_SCAN (1U << 5)
#define MT7921_SCAN_SSID_TYPE_WILDCARD 0x01U
#define MT7921_SCAN_SSID_TYPE_SPECIFIED_WILDCARD 0x04U
#define MT7921_SCAN_SSID_TYPE_EXT_SPECIFIED 0x01U
#define MT7921_SCAN_CHANNEL_TYPE_FULL 0U
#define MT7921_SCAN_CHANNEL_TYPE_SPECIFIED 4U
#define MT7921_WF_RFCR_DROP_OTHER_BEACON (1U << 11)
#define MT7921_RX_FILTER_BIT_CLR (1U << 1)
#define MT7921_CH_SWITCH_NORMAL 0U
#define MT7921_CH_SWITCH_SCAN_BYPASS_DPD 9U

#define MT7921_PIPE_DATA_IN(priv) ((priv)->in_pipes[MT_EP_IN_PKT_RX])
#define MT7921_PIPE_MCU_IN(priv) ((priv)->in_pipes[MT_EP_IN_CMD_RESP])
#define MT7921_PIPE_MCU_OUT(priv) ((priv)->out_pipes[MT_EP_OUT_INBAND_CMD])
#define MT7921_PIPE_DATA_OUT(priv) ((priv)->out_pipes[MT_EP_OUT_AC_BE])
#define MT7921_PIPE_FWDL_OUT(priv) ((priv)->out_pipes[MT_EP_OUT_AC_BE])

struct mt7921_patch_hdr {
    char build_date[16];
    char platform[4];
    uint32_t hw_sw_ver_be;
    uint32_t patch_ver_be;
    uint16_t checksum_be;
    uint16_t rsv;
    struct {
        uint32_t patch_ver_be;
        uint32_t subsys_be;
        uint32_t feature_be;
        uint32_t n_region_be;
        uint32_t crc_be;
        uint32_t rsv[11];
    } desc;
} __attribute__((packed));

struct mt7921_patch_sec {
    uint32_t type_be;
    uint32_t offs_be;
    uint32_t size_be;
    union {
        uint32_t spec[13];
        struct {
            uint32_t addr_be;
            uint32_t len_be;
            uint32_t sec_key_idx_be;
            uint32_t align_len_be;
            uint32_t rsv[9];
        } info;
    };
} __attribute__((packed));

struct mt7921_fw_trailer {
    uint8_t chip_id;
    uint8_t eco_code;
    uint8_t n_region;
    uint8_t format_ver;
    uint8_t format_flag;
    uint8_t rsv[2];
    char fw_ver[10];
    char build_date[15];
    uint32_t crc_le;
} __attribute__((packed));

struct mt7921_fw_region {
    uint32_t decomp_crc_le;
    uint32_t decomp_len_le;
    uint32_t decomp_blk_sz_le;
    uint8_t rsv0[4];
    uint32_t addr_le;
    uint32_t len_le;
    uint8_t feature_set;
    uint8_t type;
    uint8_t rsv1[14];
} __attribute__((packed));

struct mt7921_mcu_patch_sem_req {
    uint32_t op;
} __attribute__((packed));

struct mt7921_mcu_patch_finish_req {
    uint8_t check_crc;
    uint8_t reserved[3];
} __attribute__((packed));

struct mt7921_mcu_init_download_req {
    uint32_t addr;
    uint32_t len;
    uint32_t mode;
} __attribute__((packed));

struct mt7921_mcu_fw_start_req {
    uint32_t option;
    uint32_t addr;
} __attribute__((packed));

struct mt7921_mcu_txd {
    uint32_t txd[8];
    uint16_t len;
    uint16_t pq_id;
    uint8_t cid;
    uint8_t pkt_type;
    uint8_t set_query;
    uint8_t seq;
    uint8_t uc_d2b0_rev;
    uint8_t ext_cid;
    uint8_t s2d_index;
    uint8_t ext_cid_ack;
    uint32_t rsv[5];
} __attribute__((packed));

struct mt7921_mcu_ce_fwlog_req {
    uint8_t ctrl_val;
    uint8_t pad[3];
} __attribute__((packed));

struct mt7921_cap_hdr {
    uint16_t n_element_le;
    uint8_t rsv[2];
} __attribute__((packed));

struct mt7921_cap_tlv {
    uint32_t type_le;
    uint32_t len_le;
} __attribute__((packed));

struct mt7921_phy_cap {
    uint8_t ht;
    uint8_t vht;
    uint8_t cap_5g;
    uint8_t max_bw;
    uint8_t nss;
    uint8_t dbdc;
    uint8_t tx_ldpc;
    uint8_t rx_ldpc;
    uint8_t tx_stbc;
    uint8_t rx_stbc;
    uint8_t hw_path;
    uint8_t he;
} __attribute__((packed));

struct mt7921_mcu_scan_ssid {
    uint32_t ssid_len_le;
    uint8_t ssid[32];
} __attribute__((packed));

struct mt7921_mcu_scan_channel {
    uint8_t band;
    uint8_t channel_num;
} __attribute__((packed));

struct mt7921_mcu_hw_scan_req {
    uint8_t seq_num;
    uint8_t bss_idx;
    uint8_t scan_type;
    uint8_t ssid_type;
    uint8_t ssids_num;
    uint8_t probe_req_num;
    uint8_t scan_func;
    uint8_t version;
    struct mt7921_mcu_scan_ssid ssids[4];
    uint16_t probe_delay_time_le;
    uint16_t channel_dwell_time_le;
    uint16_t timeout_value_le;
    uint8_t channel_type;
    uint8_t channels_num;
    struct mt7921_mcu_scan_channel channels[32];
    uint16_t ies_len_le;
    uint8_t ies[600];
    uint8_t ext_channels_num;
    uint8_t ext_ssids_num;
    uint16_t channel_min_dwell_time_le;
    struct mt7921_mcu_scan_channel ext_channels[32];
    struct mt7921_mcu_scan_ssid ext_ssids[6];
    uint8_t bssid[6];
    uint8_t random_mac[6];
    uint8_t pad[63];
    uint8_t ssid_type_ext;
} __attribute__((packed));

struct mt7921_mcu_cancel_scan_req {
    uint8_t seq_num;
    uint8_t is_ext_channel;
    uint8_t rsv[2];
} __attribute__((packed));

static uint32_t mt7921_be32_to_cpu(uint32_t v) {
    return ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) |
           ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);
}

static uint32_t mt7921_le32_to_cpu(uint32_t v) { return v; }
static uint16_t mt7921_le16_to_cpu(uint16_t v) { return v; }
static uint32_t mt7921_cpu_to_le32(uint32_t v) { return v; }
static uint16_t mt7921_cpu_to_le16(uint16_t v) { return v; }

static size_t mt7921_min_size(size_t a, size_t b) {
    if (a < b) {
        return a;
    }
    return b;
}

static uint16_t mt7921_load_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t mt7921_load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t mt7921_get_field(uint32_t val, uint32_t mask, uint32_t shift) {
    return (val & mask) >> shift;
}

static uint32_t mt7921_set_field(uint32_t reg, uint32_t value, uint32_t mask,
                                 uint32_t shift) {
    reg &= ~mask;
    reg |= (value << shift) & mask;
    return reg;
}

static bool mt7921_is_multicast_addr(const uint8_t *addr) {
    return (addr[0] & 0x01U) != 0;
}

static uint8_t mt7921_popcount8(uint8_t v) {
    uint8_t c = 0;

    while (v) {
        c += (uint8_t)(v & 1U);
        v >>= 1;
    }

    return c;
}

static uint8_t mt7921_tid_to_ac(uint8_t tid) {
    switch (tid & 0x7U) {
    case 1:
    case 2:
        return 1;
    case 4:
    case 5:
        return 2;
    case 6:
    case 7:
        return 3;
    case 0:
    case 3:
    default:
        return 0;
    }
}

static uint8_t mt7921_lmac_queue_from_tid(uint8_t tid) {
    uint8_t ac = mt7921_tid_to_ac(tid);

    switch (ac) {
    case 0:
        return MT7921_LMAC_AC03;
    case 1:
        return MT7921_LMAC_AC02;
    case 2:
        return MT7921_LMAC_AC01;
    case 3:
        return MT7921_LMAC_AC00;
    default:
        return MT7921_LMAC_AC03;
    }
}

static uint32_t mt7921_ieee80211_hdr_len(uint16_t fc) {
    uint32_t len = 24;
    uint8_t type = (uint8_t)((fc >> 2) & 0x3U);
    uint8_t subtype = (uint8_t)((fc >> 4) & 0xfU);
    bool to_ds = (fc & (1U << 8)) != 0;
    bool from_ds = (fc & (1U << 9)) != 0;

    if (type == 2U && (subtype & 0x8U)) {
        len += 2;
    }
    if (to_ds && from_ds) {
        len += 6;
    }

    return len;
}

static int mt7921_build_txwi(mt7921_priv_t *priv, const uint8_t *frame,
                             uint32_t frame_len, uint8_t *txwi,
                             uint32_t txwi_len) {
    uint16_t fc;
    uint8_t type;
    uint8_t subtype;
    uint8_t tid = 0;
    uint32_t hdr_len;
    uint32_t w0 = 0;
    uint32_t w1 = 0;
    uint32_t w2 = 0;
    uint32_t w3 = 0;
    uint32_t w8 = 0;
    uint8_t q_idx = MT7921_LMAC_AC03;

    if (!priv || !frame || !txwi || txwi_len < MT7921_TXWI_SIZE ||
        frame_len < 24) {
        return -EINVAL;
    }

    fc = mt7921_load_le16(frame);
    type = (uint8_t)((fc >> 2) & 0x3U);
    subtype = (uint8_t)((fc >> 4) & 0xfU);
    hdr_len = mt7921_ieee80211_hdr_len(fc);

    if (hdr_len > frame_len) {
        return -EINVAL;
    }

    if (type == 2U && (subtype & 0x8U) && hdr_len >= 26U) {
        tid = frame[24] & 0x0fU;
        q_idx = mt7921_lmac_queue_from_tid(tid);
    } else if (type == 0U) {
        q_idx = MT7921_LMAC_AC00;
    }

    memset(txwi, 0, txwi_len);

    w0 = mt7921_set_field(w0, frame_len + MT7921_TXWI_SIZE,
                          MT7921_TXD0_TX_BYTES_MASK, 0);
    w0 = mt7921_set_field(w0, MT7921_TX_TYPE_SF,
                          (0x3U << MT7921_TXD0_PKT_FMT_SHIFT),
                          MT7921_TXD0_PKT_FMT_SHIFT);
    w0 = mt7921_set_field(w0, q_idx, (0x7fU << MT7921_TXD0_Q_IDX_SHIFT),
                          MT7921_TXD0_Q_IDX_SHIFT);

    w1 |= MT7921_TXD1_LONG_FORMAT;
    w1 = mt7921_set_field(w1, priv->tx_own_mac_idx,
                          (0x3fU << MT7921_TXD1_OWN_MAC_SHIFT),
                          MT7921_TXD1_OWN_MAC_SHIFT);
    w1 = mt7921_set_field(w1, tid, (0x7U << MT7921_TXD1_TID_SHIFT),
                          MT7921_TXD1_TID_SHIFT);
    w1 = mt7921_set_field(w1, MT7921_HDR_FORMAT_80211,
                          (0x3U << MT7921_TXD1_HDR_FORMAT_SHIFT),
                          MT7921_TXD1_HDR_FORMAT_SHIFT);
    w1 = mt7921_set_field(w1, hdr_len / 2U,
                          (0x1fU << MT7921_TXD1_HDR_INFO_SHIFT),
                          MT7921_TXD1_HDR_INFO_SHIFT);
    w1 = mt7921_set_field(w1, priv->tx_wlan_idx, MT7921_TXD1_WLAN_IDX_MASK, 0);

    w2 = mt7921_set_field(w2, type, (0x3U << MT7921_TXD2_FRAME_TYPE_SHIFT),
                          MT7921_TXD2_FRAME_TYPE_SHIFT);
    w2 = mt7921_set_field(w2, subtype, (0xfU << MT7921_TXD2_SUB_TYPE_SHIFT),
                          MT7921_TXD2_SUB_TYPE_SHIFT);
    if (mt7921_is_multicast_addr(frame + 4)) {
        w2 |= MT7921_TXD2_MULTICAST;
    }
    if (type == 0U) {
        w2 |= MT7921_TXD2_FIX_RATE;
    }

    w3 = mt7921_set_field(w3, 15U, (0x1fU << MT7921_TXD3_REM_TX_COUNT_SHIFT),
                          MT7921_TXD3_REM_TX_COUNT_SHIFT);

    w8 = mt7921_set_field(w8, type, (0x3U << MT7921_TXD8_L_TYPE_SHIFT),
                          MT7921_TXD8_L_TYPE_SHIFT);
    w8 = mt7921_set_field(w8, subtype, (0xfU << MT7921_TXD8_L_SUB_TYPE_SHIFT),
                          MT7921_TXD8_L_SUB_TYPE_SHIFT);

    memcpy(txwi + 0, &w0, sizeof(w0));
    memcpy(txwi + 4, &w1, sizeof(w1));
    memcpy(txwi + 8, &w2, sizeof(w2));
    memcpy(txwi + 12, &w3, sizeof(w3));
    memcpy(txwi + 32, &w8, sizeof(w8));

    return 0;
}

static int mt7921_strip_rx_desc(const uint8_t *pkt, uint32_t pkt_len,
                                const uint8_t **frame, uint32_t *frame_len) {
    uint32_t rxd0;
    uint32_t rxd1;
    uint32_t rxd2;
    uint32_t type;
    uint32_t flag;
    uint32_t words = 6;
    uint32_t remove_pad;
    uint32_t hdr_len;

    if (!pkt || !frame || !frame_len || pkt_len < 24) {
        return -EINVAL;
    }

    rxd0 = mt7921_load_le32(pkt + 0);
    rxd1 = mt7921_load_le32(pkt + 4);
    rxd2 = mt7921_load_le32(pkt + 8);

    type = mt7921_get_field(rxd0, MT7921_RXD0_PKT_TYPE_MASK,
                            MT7921_RXD0_PKT_TYPE_SHIFT);
    flag = mt7921_get_field(rxd0, MT7921_RXD0_PKT_FLAG_MASK,
                            MT7921_RXD0_PKT_FLAG_SHIFT);
    if (type == MT7921_PKT_TYPE_RX_EVENT && flag == 1U) {
        type = MT7921_PKT_TYPE_NORMAL_MCU;
    }
    if (type != MT7921_PKT_TYPE_NORMAL) {
        return -EAGAIN;
    }

    if (rxd1 & MT7921_RXD1_GROUP_4) {
        words += 4;
    }
    if (rxd1 & MT7921_RXD1_GROUP_1) {
        words += 4;
    }
    if (rxd1 & MT7921_RXD1_GROUP_2) {
        words += 2;
    }
    if (rxd1 & MT7921_RXD1_GROUP_3) {
        words += 2;
        if (rxd1 & MT7921_RXD1_GROUP_5) {
            words += 18;
        }
    }

    remove_pad = mt7921_get_field(rxd2, MT7921_RXD2_HDR_OFFSET_MASK,
                                  MT7921_RXD2_HDR_OFFSET_SHIFT);
    hdr_len = words * 4U + remove_pad * 2U;
    if (hdr_len >= pkt_len) {
        return -EINVAL;
    }

    *frame = pkt + hdr_len;
    *frame_len = pkt_len - hdr_len;

    return 0;
}

static int mt7921_tx_raw(void *driver, const void *buf, uint32_t len);
static int mt7921_rx_raw(void *driver, void *buf, uint32_t len);
static int mt7921_mcu_send_msg(mt7921_priv_t *priv, uint32_t cmd, void *req,
                               size_t req_len, bool wait_resp, void *resp,
                               size_t resp_len);
static int mt7921_mcu_set_scan_channel(mt7921_priv_t *priv, uint8_t band,
                                       uint8_t channel, uint8_t switch_reason,
                                       bool wait_resp);

static void mt7921_store_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
}

static bool mt7921_is_mgmt_subtype(const uint8_t *frame, uint32_t len,
                                   uint8_t subtype) {
    uint16_t fc;
    uint8_t type;
    uint8_t st;

    if (!frame || len < 24) {
        return false;
    }

    fc = mt7921_load_le16(frame);
    type = (uint8_t)((fc >> 2) & 0x3U);
    st = (uint8_t)((fc >> 4) & 0xfU);

    return type == 0U && st == subtype;
}

static int mt7921_parse_mgmt_ssid(const uint8_t *frame, uint32_t frame_len,
                                  uint8_t *ssid, uint8_t *ssid_len,
                                  uint32_t ssid_capacity, uint8_t *channel) {
    uint16_t fc;
    uint8_t type;
    uint8_t subtype;
    uint32_t offset;
    bool ssid_found = false;

    if (!frame || !ssid || !ssid_len || ssid_capacity == 0) {
        return -EINVAL;
    }
    if (frame_len < 36) {
        return -EINVAL;
    }

    fc = mt7921_load_le16(frame);
    type = (uint8_t)((fc >> 2) & 0x3U);
    subtype = (uint8_t)((fc >> 4) & 0xfU);
    if (type != 0U || (subtype != 8U && subtype != 5U)) {
        return -EOPNOTSUPP;
    }

    if (channel) {
        *channel = 0;
    }
    *ssid_len = 0;

    offset = 24 + 12;
    while (offset + 2 <= frame_len) {
        uint8_t id = frame[offset];
        uint8_t len = frame[offset + 1];
        uint32_t copy_len;

        offset += 2;
        if (offset + len > frame_len) {
            break;
        }

        if (id == 0) {
            copy_len = len;
            if (copy_len > ssid_capacity) {
                copy_len = ssid_capacity;
            }
            memcpy(ssid, frame + offset, copy_len);
            *ssid_len = (uint8_t)copy_len;
            ssid_found = true;
        } else if (id == 3 && len >= 1 && channel) {
            *channel = frame[offset];
        }

        offset += len;
    }

    if (!ssid_found) {
        return -ENOENT;
    }

    return 0;
}

static int mt7921_wait_mgmt_frame(mt7921_priv_t *priv, uint8_t subtype,
                                  const uint8_t bssid[6], uint8_t *buf,
                                  uint32_t buf_len, uint32_t *out_len,
                                  uint64_t timeout_ms) {
    uint64_t start = nano_time();
    int ret;

    if (!priv || !buf || !out_len) {
        return -EINVAL;
    }

    while ((nano_time() - start) < timeout_ms * 1000000ULL) {
        ret = mt7921_rx_raw(priv, buf, buf_len);
        if (ret <= 0) {
            continue;
        }
        if (!mt7921_is_mgmt_subtype(buf, (uint32_t)ret, subtype)) {
            continue;
        }
        if (bssid && memcmp(buf + 10, bssid, 6) != 0) {
            continue;
        }

        *out_len = (uint32_t)ret;
        return 0;
    }

    return -ETIMEDOUT;
}

static void mt7921_update_link_state(mt7921_priv_t *priv, bool connected) {
    if (!priv || !priv->rtnl_dev) {
        return;
    }

    spin_lock(&priv->rtnl_dev->lock);
    if (connected) {
        priv->rtnl_dev->flags |= IFF_RUNNING | IFF_LOWER_UP;
        if (priv->rtnl_dev->flags & IFF_UP) {
            priv->rtnl_dev->operstate = IF_OPER_UP;
        }
    } else {
        priv->rtnl_dev->flags &= ~(IFF_RUNNING | IFF_LOWER_UP);
        if (priv->rtnl_dev->flags & IFF_UP) {
            priv->rtnl_dev->operstate = IF_OPER_DORMANT;
        }
    }
    spin_unlock(&priv->rtnl_dev->lock);

    rtnl_notify_link(priv->rtnl_dev, RTM_NEWLINK);
}

static int mt7921_mcu_start_hw_scan(mt7921_priv_t *priv, const char *ssid,
                                    uint8_t ssid_len) {
    struct mt7921_mcu_hw_scan_req req;
    static const struct {
        uint8_t band;
        uint8_t channel;
    } default_channels[] = {
        {1, 1},  {1, 2},  {1, 3},  {1, 4},   {1, 5},   {1, 6},   {1, 7},
        {1, 8},  {1, 9},  {1, 10}, {1, 11},  {1, 12},  {1, 13},  {2, 36},
        {2, 40}, {2, 44}, {2, 48}, {2, 149}, {2, 153}, {2, 157}, {2, 161},
    };
    uint8_t n_ssids = 0;
    uint8_t i;
    uint16_t duration = 0;
    uint16_t timeout;

    if (!priv || ssid_len > 32 || (ssid_len != 0 && !ssid)) {
        return -EINVAL;
    }

    memset(&req, 0, sizeof(req));
    priv->scan_seq = (uint8_t)((priv->scan_seq + 1U) & 0x7fU);
    if (!priv->scan_seq) {
        priv->scan_seq = 1;
    }

    req.seq_num = (uint8_t)(priv->scan_seq & 0x7fU);
    req.bss_idx = 0;
    req.scan_type = ssid_len ? 1U : 0U;
    req.probe_req_num = ssid_len ? 2U : 0U;
    req.version = 1;

    if (ssid_len) {
        req.ssids[0].ssid_len_le = mt7921_cpu_to_le32((uint32_t)ssid_len);
        memcpy(req.ssids[0].ssid, ssid, ssid_len);
        n_ssids = 1;
        req.ssid_type = MT7921_SCAN_SSID_TYPE_SPECIFIED_WILDCARD;
        req.ssid_type_ext = MT7921_SCAN_SSID_TYPE_EXT_SPECIFIED;
    } else {
        req.ssid_type = MT7921_SCAN_SSID_TYPE_WILDCARD;
        req.ssid_type_ext = 0;
    }

    req.ssids_num = n_ssids;
    req.scan_func = MT7921_SCAN_FUNC_SPLIT_SCAN;
    req.probe_delay_time_le = mt7921_cpu_to_le16(0);

    req.channel_type = MT7921_SCAN_CHANNEL_TYPE_SPECIFIED;
    req.channels_num = (uint8_t)mt7921_min_size(
        sizeof(default_channels) / sizeof(default_channels[0]), 32U);
    req.ext_channels_num = 0;

    for (i = 0; i < req.channels_num; i++) {
        req.channels[i].band = default_channels[i].band;
        req.channels[i].channel_num = default_channels[i].channel;
    }

    timeout = (uint16_t)(req.channels_num * duration);
    req.channel_dwell_time_le = mt7921_cpu_to_le16(duration);
    req.channel_min_dwell_time_le = mt7921_cpu_to_le16(duration);
    req.timeout_value_le = mt7921_cpu_to_le16(timeout);

    req.ext_ssids_num = 0;
    req.ies_len_le = mt7921_cpu_to_le16(0);
    memset(req.random_mac, 0, sizeof(req.random_mac));
    memset(req.bssid, 0, sizeof(req.bssid));

    printk("mt7921: start_hw_scan seq=%u type=%u ssids=%u ch_type=%u ch_num=%u "
           "dwell=%u timeout=%u\n",
           req.seq_num, req.scan_type, req.ssids_num, req.channel_type,
           req.channels_num, mt7921_le16_to_cpu(req.channel_dwell_time_le),
           mt7921_le16_to_cpu(req.timeout_value_le));

    {
        uint32_t scan_ack = 0;
        int ret;

        ret =
            mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_START_HW_SCAN, &req,
                                sizeof(req), true, &scan_ack, sizeof(scan_ack));
        printk("mt7921: start_hw_scan ack ret=%d val=0x%08x\n", ret, scan_ack);
        return ret;
    }
}

static int mt7921_mcu_cancel_hw_scan(mt7921_priv_t *priv) {
    struct mt7921_mcu_cancel_scan_req req;

    if (!priv) {
        return -EINVAL;
    }

    memset(&req, 0, sizeof(req));
    req.seq_num = priv->scan_seq;
    return mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_CANCEL_HW_SCAN, &req,
                               sizeof(req), false, NULL, 0);
}

static int mt7921_usb_bulk_send(mt7921_priv_t *priv, struct usb_pipe *pipe,
                                const uint8_t *payload, size_t payload_len);
static int mt7921_usb_bulk_recv(mt7921_priv_t *priv, struct usb_pipe *pipe,
                                uint8_t *buf, size_t len);
static int mt7921_usb_bulk_recv_nonblock(mt7921_priv_t *priv,
                                         struct usb_pipe *pipe, uint8_t *buf,
                                         size_t len);
static int mt7921_usb_bulk_recv_timeout(mt7921_priv_t *priv,
                                        struct usb_pipe *pipe, uint8_t *buf,
                                        size_t len, uint64_t timeout_us);

struct mt7921_scan_diag {
    uint32_t ep_data_empty;
    uint32_t ep_mcu_empty;
    uint32_t ep_data_pkt;
    uint32_t ep_mcu_pkt;
    uint32_t pkt_normal;
    uint32_t pkt_event;
    uint32_t pkt_other;
    uint32_t pkt_bad_len;
    uint32_t sample_logs;
};

static int mt7921_scan_poll_frame(mt7921_priv_t *priv, uint8_t *out,
                                  uint32_t out_len,
                                  struct mt7921_scan_diag *diag) {
    struct usb_pipe *pipes[2];
    uint8_t rx_buf[MT7921_USB_BULK_BUF_SIZE];
    const uint8_t *frame;
    uint32_t rxd0;
    uint32_t pkt_len;
    uint32_t frame_len;
    uint32_t copy_len;
    uint32_t type;
    int i;
    int ret;

    if (!priv || !out || out_len == 0) {
        return -EINVAL;
    }

    pipes[0] = MT7921_PIPE_DATA_IN(priv);
    pipes[1] = MT7921_PIPE_MCU_IN(priv);

    for (i = 0; i < 2; i++) {
        if (!pipes[i]) {
            continue;
        }

        memset(rx_buf, 0, sizeof(rx_buf));
        mutex_lock(&priv->io_lock);
        ret = mt7921_usb_bulk_recv_timeout(priv, pipes[i], rx_buf,
                                           sizeof(rx_buf), 2000);
        mutex_unlock(&priv->io_lock);
        if (ret) {
            if (diag) {
                if (i == 0) {
                    diag->ep_data_empty++;
                } else {
                    diag->ep_mcu_empty++;
                }
            }
            continue;
        }

        if (diag) {
            if (i == 0) {
                diag->ep_data_pkt++;
            } else {
                diag->ep_mcu_pkt++;
            }
        }

        pkt_len = mt7921_load_le16(rx_buf);
        if (pkt_len < 24U ||
            pkt_len > (uint32_t)(sizeof(rx_buf) - MT7921_SDIO_HDR_SIZE)) {
            if (diag) {
                diag->pkt_bad_len++;
                if (diag->sample_logs < 8) {
                    diag->sample_logs++;
                    printk("mt7921: scan raw ep=%s b0=%02x b1=%02x b2=%02x "
                           "b3=%02x b4=%02x b5=%02x b6=%02x b7=%02x\n",
                           i == 0 ? "data" : "mcu", rx_buf[0], rx_buf[1],
                           rx_buf[2], rx_buf[3], rx_buf[4], rx_buf[5],
                           rx_buf[6], rx_buf[7]);
                }
            }
            continue;
        }

        rxd0 = mt7921_load_le32(rx_buf + MT7921_SDIO_HDR_SIZE);
        type = mt7921_get_field(rxd0, MT7921_RXD0_PKT_TYPE_MASK,
                                MT7921_RXD0_PKT_TYPE_SHIFT);

        if (type == MT7921_PKT_TYPE_NORMAL) {
            if (diag) {
                diag->pkt_normal++;
            }
        } else if (type == MT7921_PKT_TYPE_RX_EVENT ||
                   type == MT7921_PKT_TYPE_NORMAL_MCU) {
            if (diag) {
                diag->pkt_event++;
            }
            continue;
        } else {
            if (diag) {
                diag->pkt_other++;
            }
            continue;
        }

        ret = mt7921_strip_rx_desc(rx_buf + MT7921_SDIO_HDR_SIZE, pkt_len,
                                   &frame, &frame_len);
        if (ret) {
            continue;
        }

        if (!mt7921_is_mgmt_subtype(frame, frame_len, 8U) &&
            !mt7921_is_mgmt_subtype(frame, frame_len, 5U)) {
            continue;
        }

        copy_len = frame_len;
        if (copy_len > out_len) {
            copy_len = out_len;
        }
        memcpy(out, frame, copy_len);
        return (int)copy_len;
    }

    return 0;
}

static int mt7921_send_probe_req(mt7921_priv_t *priv, const char *ssid,
                                 uint8_t ssid_len) {
    uint8_t frame[96];
    uint16_t seq_ctrl;
    uint32_t off = 0;
    int ret;

    if (!priv || (ssid_len && !ssid) || ssid_len > 32) {
        return -EINVAL;
    }

    memset(frame, 0, sizeof(frame));
    mt7921_store_le16(frame + 0, 0x0040U);
    mt7921_store_le16(frame + 2, 0U);
    memset(frame + 4, 0xff, 6);
    memcpy(frame + 10, priv->macaddr, 6);
    memset(frame + 16, 0xff, 6);
    seq_ctrl = (uint16_t)((priv->mgmt_seq++ & 0x0fffU) << 4);
    mt7921_store_le16(frame + 22, seq_ctrl);
    off = 24;

    frame[off++] = 0;
    frame[off++] = ssid_len;
    if (ssid_len) {
        memcpy(frame + off, ssid, ssid_len);
        off += ssid_len;
    }

    frame[off++] = 1;
    frame[off++] = 8;
    frame[off++] = 0x82;
    frame[off++] = 0x84;
    frame[off++] = 0x8b;
    frame[off++] = 0x96;
    frame[off++] = 0x0c;
    frame[off++] = 0x12;
    frame[off++] = 0x18;
    frame[off++] = 0x24;

    ret = mt7921_tx_raw(priv, frame, off);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int mt7921_soft_scan_find_bssid(mt7921_priv_t *priv, const char *ssid,
                                       uint8_t ssid_len, uint8_t bssid[6]) {
    static const struct {
        uint8_t band;
        uint8_t channel;
    } scan_channels[] = {
        {0, 1},  {0, 2},  {0, 3},  {0, 4},   {0, 5},   {0, 6},   {0, 7},
        {0, 8},  {0, 9},  {0, 10}, {0, 11},  {0, 12},  {0, 13},  {1, 36},
        {1, 40}, {1, 44}, {1, 48}, {1, 149}, {1, 153}, {1, 157}, {1, 161},
    };
    uint8_t frame[IEEE80211_MAX_FRAME_LEN];
    uint8_t found_ssid[32];
    uint8_t found_ssid_len = 0;
    uint8_t ch;
    size_t i;
    int ret;
    uint64_t start;
    struct mt7921_scan_diag diag;

    memset(&diag, 0, sizeof(diag));
    memset(found_ssid, 0, sizeof(found_ssid));

    for (i = 0; i < sizeof(scan_channels) / sizeof(scan_channels[0]); i++) {
        ret = mt7921_mcu_set_scan_channel(
            priv, scan_channels[i].band, scan_channels[i].channel,
            MT7921_CH_SWITCH_SCAN_BYPASS_DPD, false);
        if (ret) {
            continue;
        }

        ret = mt7921_send_probe_req(priv, ssid, ssid_len);
        if (ret) {
            continue;
        }

        start = nano_time();
        while ((nano_time() - start) < 80ULL * 1000000ULL) {
            ret = mt7921_scan_poll_frame(priv, frame, sizeof(frame), &diag);
            if (ret <= 0) {
                delay_us(5000);
                continue;
            }

            ch = 0;
            if (mt7921_parse_mgmt_ssid(frame, (uint32_t)ret, found_ssid,
                                       &found_ssid_len, sizeof(found_ssid),
                                       &ch) < 0) {
                continue;
            }

            if (found_ssid_len == ssid_len &&
                memcmp(found_ssid, ssid, ssid_len) == 0) {
                memcpy(bssid, frame + 16, 6);
                printk("mt7921: soft scan hit data_pkt=%u mcu_pkt=%u "
                       "data_empty=%u mcu_empty=%u normal=%u event=%u "
                       "other=%u\n",
                       diag.ep_data_pkt, diag.ep_mcu_pkt, diag.ep_data_empty,
                       diag.ep_mcu_empty, diag.pkt_normal, diag.pkt_event,
                       diag.pkt_other);
                return 0;
            }
        }
    }

    printk("mt7921: soft scan timeout data_pkt=%u mcu_pkt=%u data_empty=%u "
           "mcu_empty=%u normal=%u event=%u other=%u\n",
           diag.ep_data_pkt, diag.ep_mcu_pkt, diag.ep_data_empty,
           diag.ep_mcu_empty, diag.pkt_normal, diag.pkt_event, diag.pkt_other);
    return -ENOENT;
}

static int mt7921_scan_find_bssid(mt7921_priv_t *priv, const char *ssid,
                                  uint8_t ssid_len, uint8_t bssid[6]) {
    uint8_t frame[IEEE80211_MAX_FRAME_LEN];
    uint8_t found_ssid[32];
    uint8_t found_ssid_len = 0;
    uint8_t ch;
    struct mt7921_scan_diag diag;
    uint64_t start;
    int ret;

    if (!priv || !ssid || ssid_len == 0 || ssid_len > 32 || !bssid) {
        return -EINVAL;
    }

    memset(found_ssid, 0, sizeof(found_ssid));
    memset(&diag, 0, sizeof(diag));

    ret = mt7921_mcu_start_hw_scan(priv, NULL, 0);
    if (ret) {
        printk("mt7921: start hw scan failed: %d\n", ret);
        return ret;
    }

    start = nano_time();
    while ((nano_time() - start) < 5000ULL * 1000000ULL) {
        ret = mt7921_scan_poll_frame(priv, frame, sizeof(frame), &diag);
        if (ret <= 0) {
            delay_us(5000);
            continue;
        }

        ch = 0;
        if (mt7921_parse_mgmt_ssid(frame, (uint32_t)ret, found_ssid,
                                   &found_ssid_len, sizeof(found_ssid),
                                   &ch) < 0) {
            continue;
        }

        if (found_ssid_len == ssid_len &&
            memcmp(found_ssid, ssid, ssid_len) == 0) {
            memcpy(bssid, frame + 16, 6);
            mt7921_mcu_cancel_hw_scan(priv);
            printk("mt7921: hw scan hit data_pkt=%u mcu_pkt=%u data_empty=%u "
                   "mcu_empty=%u normal=%u event=%u other=%u\n",
                   diag.ep_data_pkt, diag.ep_mcu_pkt, diag.ep_data_empty,
                   diag.ep_mcu_empty, diag.pkt_normal, diag.pkt_event,
                   diag.pkt_other);
            return 0;
        }
    }

    mt7921_mcu_cancel_hw_scan(priv);
    printk("mt7921: hw scan timeout data_pkt=%u mcu_pkt=%u data_empty=%u "
           "mcu_empty=%u normal=%u event=%u other=%u\n",
           diag.ep_data_pkt, diag.ep_mcu_pkt, diag.ep_data_empty,
           diag.ep_mcu_empty, diag.pkt_normal, diag.pkt_event, diag.pkt_other);
    return -ENOENT;
}

static int mt7921_send_auth_open(mt7921_priv_t *priv, const uint8_t bssid[6]) {
    uint8_t frame[32];
    uint8_t resp[IEEE80211_MAX_FRAME_LEN];
    uint32_t resp_len = 0;
    uint16_t seq_ctrl;
    uint16_t status;
    int ret;

    memset(frame, 0, sizeof(frame));
    mt7921_store_le16(frame + 0, 0x00b0U);
    mt7921_store_le16(frame + 2, 0U);
    memcpy(frame + 4, bssid, 6);
    memcpy(frame + 10, priv->macaddr, 6);
    memcpy(frame + 16, bssid, 6);
    seq_ctrl = (uint16_t)((priv->mgmt_seq++ & 0x0fffU) << 4);
    mt7921_store_le16(frame + 22, seq_ctrl);

    mt7921_store_le16(frame + 24, 0U);
    mt7921_store_le16(frame + 26, 1U);
    mt7921_store_le16(frame + 28, 0U);

    ret = mt7921_tx_raw(priv, frame, 30);
    if (ret < 0) {
        return ret;
    }

    ret = mt7921_wait_mgmt_frame(priv, 11U, bssid, resp, sizeof(resp),
                                 &resp_len, 1500);
    if (ret) {
        return ret;
    }
    if (resp_len < 30) {
        return -EINVAL;
    }

    status = mt7921_load_le16(resp + 28);
    if (status != 0) {
        return -EACCES;
    }

    return 0;
}

static int mt7921_send_assoc_open(mt7921_priv_t *priv, const uint8_t bssid[6],
                                  const char *ssid, uint8_t ssid_len) {
    uint8_t frame[96];
    uint8_t resp[IEEE80211_MAX_FRAME_LEN];
    uint32_t resp_len = 0;
    uint16_t seq_ctrl;
    uint16_t status;
    uint32_t off = 0;
    int ret;

    memset(frame, 0, sizeof(frame));
    mt7921_store_le16(frame + 0, 0x0000U);
    mt7921_store_le16(frame + 2, 0U);
    memcpy(frame + 4, bssid, 6);
    memcpy(frame + 10, priv->macaddr, 6);
    memcpy(frame + 16, bssid, 6);
    seq_ctrl = (uint16_t)((priv->mgmt_seq++ & 0x0fffU) << 4);
    mt7921_store_le16(frame + 22, seq_ctrl);
    off = 24;

    mt7921_store_le16(frame + off, 0x0431U);
    off += 2;
    mt7921_store_le16(frame + off, 10U);
    off += 2;

    frame[off++] = 0;
    frame[off++] = ssid_len;
    memcpy(frame + off, ssid, ssid_len);
    off += ssid_len;

    frame[off++] = 1;
    frame[off++] = 8;
    frame[off++] = 0x82;
    frame[off++] = 0x84;
    frame[off++] = 0x8b;
    frame[off++] = 0x96;
    frame[off++] = 0x0c;
    frame[off++] = 0x12;
    frame[off++] = 0x18;
    frame[off++] = 0x24;

    ret = mt7921_tx_raw(priv, frame, off);
    if (ret < 0) {
        return ret;
    }

    ret = mt7921_wait_mgmt_frame(priv, 1U, bssid, resp, sizeof(resp), &resp_len,
                                 1500);
    if (ret) {
        return ret;
    }
    if (resp_len < 30) {
        return -EINVAL;
    }

    status = mt7921_load_le16(resp + 26);
    if (status != 0) {
        return -EACCES;
    }

    return 0;
}

static int mt7921_connect_open(mt7921_priv_t *priv, const char *ssid,
                               uint8_t ssid_len) {
    uint8_t bssid[6];
    int ret;

    ret = mt7921_scan_find_bssid(priv, ssid, ssid_len, bssid);
    if (ret) {
        return ret;
    }

    ret = mt7921_send_auth_open(priv, bssid);
    if (ret) {
        return ret;
    }

    ret = mt7921_send_assoc_open(priv, bssid, ssid, ssid_len);
    if (ret) {
        return ret;
    }

    ieee80211_ctx_set_bssid(&priv->wlan_if.ctx, bssid);
    mt7921_update_link_state(priv, true);
    return 0;
}

static int mt7921_connect_open_bssid(mt7921_priv_t *priv,
                                     const uint8_t bssid[6], const char *ssid,
                                     uint8_t ssid_len) {
    int ret;

    if (!priv || !bssid || !ssid || ssid_len == 0 || ssid_len > 32) {
        return -EINVAL;
    }

    ret = mt7921_send_auth_open(priv, bssid);
    if (ret) {
        return ret;
    }

    ret = mt7921_send_assoc_open(priv, bssid, ssid, ssid_len);
    if (ret) {
        return ret;
    }

    ieee80211_ctx_set_bssid(&priv->wlan_if.ctx, bssid);
    mt7921_update_link_state(priv, true);
    return 0;
}

static int mt7921_disconnect(mt7921_priv_t *priv) {
    uint8_t frame[32];
    uint16_t seq_ctrl;

    if (!priv) {
        return -EINVAL;
    }
    if (!priv->wlan_if.ctx.has_bssid) {
        return 0;
    }

    memset(frame, 0, sizeof(frame));
    mt7921_store_le16(frame + 0, 0x00c0U);
    mt7921_store_le16(frame + 2, 0U);
    memcpy(frame + 4, priv->wlan_if.ctx.bssid, 6);
    memcpy(frame + 10, priv->macaddr, 6);
    memcpy(frame + 16, priv->wlan_if.ctx.bssid, 6);
    seq_ctrl = (uint16_t)((priv->mgmt_seq++ & 0x0fffU) << 4);
    mt7921_store_le16(frame + 22, seq_ctrl);
    mt7921_store_le16(frame + 24, 3U);
    mt7921_tx_raw(priv, frame, 26);

    ieee80211_ctx_clear_bssid(&priv->wlan_if.ctx);
    mt7921_update_link_state(priv, false);

    return 0;
}

static int mt7921_usb_bulk_send(mt7921_priv_t *priv, struct usb_pipe *pipe,
                                const uint8_t *payload, size_t payload_len) {
    uint32_t hdr;
    size_t tx_len = payload_len + 4;
    size_t pad = ((tx_len + 3U) & ~3U) + 4U - tx_len;
    uint8_t *buf;
    int ret;

    buf = malloc(tx_len + pad);
    if (!buf) {
        return -ENOMEM;
    }

    hdr = (uint32_t)(payload_len & MT7921_SDIO_HDR_TX_BYTES_MASK) |
          (MT7921_SDIO_HDR_PKT_TYPE_CMD << MT7921_SDIO_HDR_PKT_TYPE_SHIFT);
    memcpy(buf, &hdr, sizeof(hdr));
    if (payload_len) {
        memcpy(buf + 4, payload, payload_len);
    }
    if (pad) {
        memset(buf + tx_len, 0, pad);
    }

    ret = usb_send_bulk(pipe, USB_DIR_OUT, buf, tx_len + pad);
    free(buf);

    if (ret) {
        return -EIO;
    }

    return 0;
}

static int mt7921_usb_bulk_recv(mt7921_priv_t *priv, struct usb_pipe *pipe,
                                uint8_t *buf, size_t len) {
    int ret;

    (void)priv;
    if (!pipe || !buf || !len) {
        return -EINVAL;
    }

    ret = usb_send_bulk(pipe, USB_DIR_IN, buf, len);
    if (ret) {
        return -EIO;
    }

    return 0;
}

static int mt7921_usb_bulk_recv_nonblock(mt7921_priv_t *priv,
                                         struct usb_pipe *pipe, uint8_t *buf,
                                         size_t len) {
    int ret;

    (void)priv;
    if (!pipe || !buf || !len) {
        return -EINVAL;
    }

    ret = usb_send_bulk_nonblock(pipe, USB_DIR_IN, buf, len);
    if (ret) {
        return -EAGAIN;
    }

    return 0;
}

static int mt7921_usb_bulk_recv_timeout(mt7921_priv_t *priv,
                                        struct usb_pipe *pipe, uint8_t *buf,
                                        size_t len, uint64_t timeout_us) {
    int ret;

    (void)priv;
    if (!pipe || !buf || !len) {
        return -EINVAL;
    }

    ret = usb_send_pipe(pipe, USB_DIR_IN, NULL, buf, len, timeout_us * 1000ULL);
    if (ret) {
        return -EAGAIN;
    }

    return 0;
}

static int mt7921_tx_raw(void *driver, const void *buf, uint32_t len) {
    mt7921_priv_t *priv = (mt7921_priv_t *)driver;
    struct usb_pipe *data_out;
    uint8_t *tx_pkt;
    int ret;

    if (!priv || !buf || !len) {
        return -EINVAL;
    }
    data_out = MT7921_PIPE_DATA_OUT(priv);
    if (!data_out) {
        return -ENODEV;
    }

    tx_pkt = malloc(MT7921_TXWI_SIZE + len);
    if (!tx_pkt) {
        return -ENOMEM;
    }

    ret = mt7921_build_txwi(priv, (const uint8_t *)buf, len, tx_pkt,
                            MT7921_TXWI_SIZE);
    if (ret) {
        free(tx_pkt);
        return ret;
    }
    memcpy(tx_pkt + MT7921_TXWI_SIZE, buf, len);

    mutex_lock(&priv->io_lock);
    ret = mt7921_usb_bulk_send(priv, data_out, tx_pkt, MT7921_TXWI_SIZE + len);
    mutex_unlock(&priv->io_lock);
    free(tx_pkt);
    if (ret) {
        return ret;
    }

    return (int)len;
}

static int mt7921_rx_raw(void *driver, void *buf, uint32_t len) {
    mt7921_priv_t *priv = (mt7921_priv_t *)driver;
    struct usb_pipe *pipes[2];
    uint8_t rx_buf[MT7921_USB_BULK_BUF_SIZE];
    const uint8_t *frame;
    uint32_t rxd0;
    uint32_t pkt_len;
    uint32_t frame_len;
    uint32_t copy_len;
    int i;
    int try_count;
    int ret;

    if (!priv || !buf || len == 0) {
        return -EINVAL;
    }
    pipes[0] = MT7921_PIPE_DATA_IN(priv);
    pipes[1] = MT7921_PIPE_MCU_IN(priv);
    if (!pipes[0] && !pipes[1]) {
        return -ENODEV;
    }

    for (try_count = 0; try_count < 64; try_count++) {
        for (i = 0; i < 2; i++) {
            if (!pipes[i]) {
                continue;
            }

            memset(rx_buf, 0, sizeof(rx_buf));
            mutex_lock(&priv->io_lock);
            ret = mt7921_usb_bulk_recv_nonblock(priv, pipes[i], rx_buf,
                                                sizeof(rx_buf));
            mutex_unlock(&priv->io_lock);
            if (ret) {
                continue;
            }

            pkt_len = mt7921_load_le16(rx_buf);
            if (pkt_len < 24U ||
                pkt_len > (uint32_t)(sizeof(rx_buf) - MT7921_SDIO_HDR_SIZE)) {
                continue;
            }

            rxd0 = mt7921_load_le32(rx_buf + MT7921_SDIO_HDR_SIZE);
            if (mt7921_get_field(rxd0, MT7921_RXD0_PKT_TYPE_MASK,
                                 MT7921_RXD0_PKT_TYPE_SHIFT) !=
                MT7921_PKT_TYPE_NORMAL) {
                continue;
            }

            ret = mt7921_strip_rx_desc(rx_buf + MT7921_SDIO_HDR_SIZE, pkt_len,
                                       &frame, &frame_len);
            if (ret == -EAGAIN) {
                continue;
            }
            if (ret) {
                return ret;
            }

            copy_len = frame_len;
            if (copy_len > len) {
                copy_len = len;
            }

            memcpy(buf, frame, copy_len);
            return (int)copy_len;
        }

        delay_us(200);
    }

    return 0;
}

static int mt7921_netdev_send(void *dev, void *data, uint32_t len) {
    mt7921_priv_t *priv = (mt7921_priv_t *)dev;

    if (!priv) {
        return -EINVAL;
    }

    return ieee80211_netif_send_eth(&priv->wlan_if, data, len);
}

static int mt7921_netdev_recv(void *dev, void *data, uint32_t len) {
    mt7921_priv_t *priv = (mt7921_priv_t *)dev;

    if (!priv) {
        return -EINVAL;
    }

    return ieee80211_netif_recv_eth(&priv->wlan_if, data, len);
}

static int mt7921_rtnl_wireless_cmd(struct net_device *dev, const void *data,
                                    uint32_t len) {
    mt7921_priv_t *priv;
    const struct rtnl_wifi_cmd_hdr *hdr;

    if (!dev || !data || len < sizeof(*hdr)) {
        return -EINVAL;
    }

    priv = (mt7921_priv_t *)dev->wireless_priv;
    if (!priv) {
        return -ENODEV;
    }

    hdr = (const struct rtnl_wifi_cmd_hdr *)data;
    if (hdr->magic != RTNL_WIFI_CMD_MAGIC ||
        hdr->version != RTNL_WIFI_CMD_VERSION) {
        return -EINVAL;
    }
    if ((uint32_t)hdr->payload_len + sizeof(*hdr) > len) {
        return -EINVAL;
    }

    switch (hdr->cmd) {
    case RTNL_WIFI_CMD_SET_TX_CTX: {
        const struct rtnl_wifi_set_tx_ctx *p =
            (const struct rtnl_wifi_set_tx_ctx *)((const uint8_t *)data +
                                                  sizeof(*hdr));
        if (hdr->payload_len < sizeof(*p)) {
            return -EINVAL;
        }
        mt7921_set_tx_context(priv, p->wlan_idx, p->own_mac_idx);
        return 0;
    }
    case RTNL_WIFI_CMD_SET_BSSID: {
        const struct rtnl_wifi_set_bssid *p =
            (const struct rtnl_wifi_set_bssid *)((const uint8_t *)data +
                                                 sizeof(*hdr));
        if (hdr->payload_len < sizeof(*p)) {
            return -EINVAL;
        }
        ieee80211_ctx_set_bssid(&priv->wlan_if.ctx, p->bssid);
        mt7921_update_link_state(priv, true);
        return 0;
    }
    case RTNL_WIFI_CMD_CONNECT_OPEN: {
        const struct rtnl_wifi_connect_open *p =
            (const struct rtnl_wifi_connect_open *)((const uint8_t *)data +
                                                    sizeof(*hdr));
        if (hdr->payload_len < sizeof(*p) || p->ssid_len == 0 ||
            p->ssid_len > 32) {
            return -EINVAL;
        }
        return mt7921_connect_open(priv, p->ssid, p->ssid_len);
    }
    case RTNL_WIFI_CMD_CONNECT_OPEN_BSSID: {
        const struct rtnl_wifi_connect_open_bssid *p =
            (const struct rtnl_wifi_connect_open_bssid *)((const uint8_t *)
                                                              data +
                                                          sizeof(*hdr));
        if (hdr->payload_len < sizeof(*p) || p->ssid_len == 0 ||
            p->ssid_len > 32) {
            return -EINVAL;
        }
        return mt7921_connect_open_bssid(priv, p->bssid, p->ssid, p->ssid_len);
    }
    case RTNL_WIFI_CMD_DISCONNECT:
        return mt7921_disconnect(priv);
    default:
        return -EOPNOTSUPP;
    }
}

static int mt7921_mcu_send_msg(mt7921_priv_t *priv, uint32_t cmd, void *req,
                               size_t req_len, bool wait_resp, void *resp,
                               size_t resp_len) {
    struct mt7921_mcu_txd txd;
    uint8_t *tx_buf = NULL;
    uint8_t rx_buf[MT7921_MCU_RX_BUF_SIZE];
    struct usb_pipe *out_pipe;
    uint8_t seq;
    uint8_t cmd_id = (uint8_t)(cmd & MT7921_MCU_CMD_FIELD_ID_MASK);
    uint8_t ext_id = (uint8_t)((cmd & MT7921_MCU_CMD_FIELD_EXT_ID_MASK) >> 8);
    int ret;
    uint8_t status;

    if (!MT7921_PIPE_MCU_IN(priv) || !MT7921_PIPE_MCU_OUT(priv)) {
        return -ENODEV;
    }

    if (cmd == MT7921_MCU_CMD_FW_SCATTER) {
        out_pipe = MT7921_PIPE_FWDL_OUT(priv) ?: MT7921_PIPE_MCU_OUT(priv);
        ret = mt7921_usb_bulk_send(priv, out_pipe, req, req_len);
        if (ret) {
            return ret;
        }
    } else {
        size_t tx_len = sizeof(txd) + req_len;

        memset(&txd, 0, sizeof(txd));
        tx_buf = calloc(1, tx_len);
        if (!tx_buf) {
            return -ENOMEM;
        }

        seq = (++priv->mcu_seq) & 0x0fU;
        if (!seq) {
            seq = (++priv->mcu_seq) & 0x0fU;
        }

        txd.txd[0] = (uint32_t)((sizeof(txd) + req_len) & 0xffffU) |
                     (2U << 23) | (0x20U << 25);
        txd.txd[1] = (1U << 31) | (1U << 16);
        txd.len = (uint16_t)((sizeof(txd) + req_len) - sizeof(txd.txd));
        txd.pq_id = 0x8000;
        txd.cid = cmd_id;
        txd.pkt_type = 0xa0;
        txd.seq = seq;
        txd.ext_cid = ext_id;
        txd.s2d_index = 0;

        if (ext_id || (cmd & MT7921_MCU_CMD_FIELD_CE)) {
            if (cmd & MT7921_MCU_CMD_FIELD_QUERY) {
                txd.set_query = 0;
            } else {
                txd.set_query = 1;
            }
            txd.ext_cid_ack = ext_id ? 1 : 0;
        } else {
            txd.set_query = 3;
        }

        memcpy(tx_buf, &txd, sizeof(txd));
        if (req_len) {
            memcpy(tx_buf + sizeof(txd), req, req_len);
        }

        ret = mt7921_usb_bulk_send(priv, MT7921_PIPE_MCU_OUT(priv), tx_buf,
                                   tx_len);
        free(tx_buf);

        if (ret) {
            return ret;
        }
    }

    if (!wait_resp) {
        return 0;
    }

    memset(rx_buf, 0, sizeof(rx_buf));
    ret = usb_send_bulk(MT7921_PIPE_DATA_IN(priv), USB_DIR_IN, rx_buf,
                        sizeof(rx_buf));
    if (ret) {
        return -EIO;
    }

    if (cmd == MT7921_MCU_CMD_PATCH_SEM_CONTROL ||
        cmd == MT7921_MCU_CMD_PATCH_FINISH_REQ) {
        status = rx_buf[32];
        if (resp && resp_len) {
            ((uint8_t *)resp)[0] = status;
            return 0;
        }
        return (int)status;
    }

    if (resp && resp_len) {
        if (36 + resp_len > sizeof(rx_buf)) {
            return -EINVAL;
        }
        memcpy(resp, rx_buf + 36, resp_len);
    }

    return 0;
}

static uint32_t mt7921_patch_get_data_mode(uint32_t info) {
    uint32_t mode = MT7921_DL_MODE_NEED_RSP;
    uint32_t enc_type = (info & MT7921_PATCH_SEC_ENC_TYPE_MASK) >>
                        MT7921_PATCH_SEC_ENC_TYPE_SHIFT;

    if (enc_type == MT7921_PATCH_SEC_ENC_TYPE_PLAIN) {
        return mode;
    }
    if (enc_type == MT7921_PATCH_SEC_ENC_TYPE_AES) {
        mode |= MT7921_DL_MODE_ENCRYPT;
        mode |= ((info & MT7921_PATCH_SEC_ENC_AES_KEY_MASK)
                 << MT7921_DL_MODE_KEY_IDX_SHIFT) &
                MT7921_DL_MODE_KEY_IDX_MASK;
        mode |= MT7921_DL_MODE_RESET_SEC_IV;
        return mode;
    }
    if (enc_type == MT7921_PATCH_SEC_ENC_TYPE_SCRAMBLE) {
        mode |= MT7921_DL_MODE_ENCRYPT;
        mode |= MT7921_DL_CONFIG_ENCRY_MODE_SEL;
        mode |= MT7921_DL_MODE_RESET_SEC_IV;
        return mode;
    }

    return mode;
}

static uint32_t mt7921_ram_get_data_mode(uint8_t feature_set) {
    uint32_t mode = MT7921_DL_MODE_NEED_RSP;

    if (feature_set & MT7921_FW_FEATURE_SET_ENCRYPT) {
        mode |= MT7921_DL_MODE_ENCRYPT;
        mode |= MT7921_DL_MODE_RESET_SEC_IV;
    }

    mode |= (((uint32_t)(feature_set & MT7921_FW_FEATURE_SET_KEY_IDX_MASK)) >>
             MT7921_FW_FEATURE_SET_KEY_IDX_SHIFT)
            << MT7921_DL_MODE_KEY_IDX_SHIFT;

    if (feature_set & MT7921_FW_FEATURE_ENCRY_MODE) {
        mode |= MT7921_DL_CONFIG_ENCRY_MODE_SEL;
    }

    return mode;
}

static int mt7921_mcu_patch_sem_ctrl(mt7921_priv_t *priv, bool get) {
    struct mt7921_mcu_patch_sem_req req;
    uint32_t sem = 0;
    int ret;

    req.op = get ? MT7921_PATCH_SEM_GET : MT7921_PATCH_SEM_RELEASE;
    ret = mt7921_mcu_send_msg(priv, MT7921_MCU_CMD_PATCH_SEM_CONTROL, &req,
                              sizeof(req), true, &sem, sizeof(sem));
    if (ret) {
        return ret;
    }

    return (int)sem;
}

static int mt7921_mcu_init_download(mt7921_priv_t *priv, uint32_t addr,
                                    uint32_t len, uint32_t mode) {
    struct mt7921_mcu_init_download_req req;
    uint8_t cmd;

    req.addr = addr;
    req.len = len;
    req.mode = mode;

    if (addr == MT7921_PATCH_ADDRESS || addr == MT7921_RAM_START_ADDRESS) {
        cmd = MT7921_MCU_CMD_PATCH_START_REQ;
    } else {
        cmd = MT7921_MCU_CMD_TARGET_ADDRESS_LEN_REQ;
    }

    return mt7921_mcu_send_msg(priv, cmd, &req, sizeof(req), true, NULL, 0);
}

static int mt7921_mcu_send_scatter(mt7921_priv_t *priv, uint8_t *data,
                                   size_t len) {
    size_t offset = 0;
    int ret;

    while (offset < len) {
        size_t chunk =
            mt7921_min_size((size_t)MT7921_MCU_SCATTER_CHUNK, len - offset);

        ret = mt7921_mcu_send_msg(priv, MT7921_MCU_CMD_FW_SCATTER,
                                  data + offset, chunk, false, NULL, 0);
        if (ret) {
            return ret;
        }
        offset += chunk;
    }

    return 0;
}

static int mt7921_mcu_start_patch(mt7921_priv_t *priv) {
    struct mt7921_mcu_patch_finish_req req;

    memset(&req, 0, sizeof(req));
    return mt7921_mcu_send_msg(priv, MT7921_MCU_CMD_PATCH_FINISH_REQ, &req,
                               sizeof(req), true, NULL, 0);
}

static int mt7921_mcu_start_firmware(mt7921_priv_t *priv, uint32_t addr,
                                     uint32_t option) {
    struct mt7921_mcu_fw_start_req req;

    req.option = option;
    req.addr = addr;
    return mt7921_mcu_send_msg(priv, MT7921_MCU_CMD_FW_START_REQ, &req,
                               sizeof(req), true, NULL, 0);
}

static void mt7921_parse_phy_cap(mt7921_priv_t *priv, const uint8_t *data,
                                 size_t len) {
    if (len < sizeof(struct mt7921_phy_cap)) {
        return;
    }

    const struct mt7921_phy_cap *cap = (const struct mt7921_phy_cap *)data;

    if (cap->nss >= 1 && cap->nss <= 8) {
        priv->antenna_mask = (uint8_t)((1U << cap->nss) - 1U);
    }
    priv->has_2ghz = (cap->hw_path & MT7921_HW_PATH_2G_BIT) != 0;
    priv->has_5ghz = (cap->hw_path & MT7921_HW_PATH_5G_BIT) != 0;
}

static int mt7921_mcu_get_nic_capability(mt7921_priv_t *priv) {
    uint8_t buf[MT7921_NIC_CAP_BUF_SIZE];
    const struct mt7921_cap_hdr *hdr;
    size_t pos;
    uint16_t n_element;
    uint16_t i;
    int ret;

    memset(buf, 0, sizeof(buf));
    ret = mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_GET_NIC_CAPAB, NULL, 0,
                              true, buf, sizeof(buf));
    if (ret) {
        return ret;
    }

    if (sizeof(buf) < sizeof(struct mt7921_cap_hdr)) {
        return -EINVAL;
    }

    hdr = (const struct mt7921_cap_hdr *)buf;
    n_element = mt7921_le16_to_cpu(hdr->n_element_le);
    pos = sizeof(*hdr);

    for (i = 0; i < n_element; i++) {
        if (pos + sizeof(struct mt7921_cap_tlv) > sizeof(buf)) {
            break;
        }

        const struct mt7921_cap_tlv *tlv =
            (const struct mt7921_cap_tlv *)(buf + pos);
        uint32_t type = mt7921_le32_to_cpu(tlv->type_le);
        uint32_t len = mt7921_le32_to_cpu(tlv->len_le);

        pos += sizeof(*tlv);
        if (pos + len > sizeof(buf)) {
            break;
        }

        if (type == MT7921_NIC_CAP_MAC_ADDR && len >= 6) {
            memcpy(priv->macaddr, buf + pos, 6);
        } else if (type == MT7921_NIC_CAP_PHY) {
            mt7921_parse_phy_cap(priv, buf + pos, len);
        } else if (type == MT7921_NIC_CAP_6G && len >= 1) {
            priv->has_6ghz = buf[pos] != 0;
        }

        pos += len;
    }

    printk("NIC CAP: mac=%02x:%02x:%02x:%02x:%02x:%02x nss_mask=0x%x 2g=%d "
           "5g=%d 6g=%d\n",
           priv->macaddr[0], priv->macaddr[1], priv->macaddr[2],
           priv->macaddr[3], priv->macaddr[4], priv->macaddr[5],
           priv->antenna_mask, priv->has_2ghz, priv->has_5ghz, priv->has_6ghz);

    return 0;
}

static int mt7921_mcu_fw_log_2_host(mt7921_priv_t *priv, uint8_t ctrl) {
    struct mt7921_mcu_ce_fwlog_req req;

    req.ctrl_val = ctrl;
    memset(req.pad, 0, sizeof(req.pad));
    return mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_FWLOG_2_HOST, &req,
                               sizeof(req), false, NULL, 0);
}

static int mt7921_mcu_set_eeprom(mt7921_priv_t *priv) {
    struct {
        uint8_t buffer_mode;
        uint8_t format;
        uint16_t len_le;
    } __attribute__((packed)) req;

    memset(&req, 0, sizeof(req));
    req.buffer_mode = 1;
    req.format = 0;
    req.len_le = mt7921_cpu_to_le16(0);

    return mt7921_mcu_send_msg(priv, MT7921_MCU_EXT_CMD_EFUSE_BUFFER_MODE, &req,
                               sizeof(req), true, NULL, 0);
}

static int mt7921_mcu_set_mac_enable(mt7921_priv_t *priv, uint8_t band,
                                     bool enable) {
    struct {
        uint8_t enable;
        uint8_t band;
        uint8_t rsv[2];
    } __attribute__((packed)) req;

    memset(&req, 0, sizeof(req));
    req.enable = enable ? 1U : 0U;
    req.band = band;

    return mt7921_mcu_send_msg(priv, MT7921_MCU_EXT_CMD_MAC_INIT_CTRL, &req,
                               sizeof(req), true, NULL, 0);
}

static int mt7921_mcu_set_channel_domain(mt7921_priv_t *priv) {
    static const uint8_t channels_2g[] = {1, 2, 3,  4,  5,  6, 7,
                                          8, 9, 10, 11, 12, 13};
    static const uint8_t channels_5g[] = {36, 40, 44, 48, 149, 153, 157, 161};
    struct {
        uint8_t alpha2[4];
        uint8_t bw_2g;
        uint8_t bw_5g;
        uint8_t bw_6g;
        uint8_t pad;
        uint8_t n_2ch;
        uint8_t n_5ch;
        uint8_t n_6ch;
        uint8_t pad2;
    } __attribute__((packed)) hdr;
    struct {
        uint16_t hw_value_le;
        uint16_t pad;
        uint32_t flags_le;
    } __attribute__((packed)) chan;
    uint8_t req[sizeof(hdr) + 64U * sizeof(chan)];
    size_t pos = 0;
    uint8_t i;

    memset(&hdr, 0, sizeof(hdr));
    hdr.alpha2[0] = '0';
    hdr.alpha2[1] = '0';
    hdr.bw_2g = 0;
    hdr.bw_5g = 3;
    hdr.bw_6g = 3;

    memcpy(req + pos, &hdr, sizeof(hdr));
    pos += sizeof(hdr);

    memset(&chan, 0, sizeof(chan));

    for (i = 0; i < (uint8_t)sizeof(channels_2g); i++) {
        chan.hw_value_le = mt7921_cpu_to_le16(channels_2g[i]);
        chan.flags_le = mt7921_cpu_to_le32(0);
        memcpy(req + pos, &chan, sizeof(chan));
        pos += sizeof(chan);
        hdr.n_2ch++;
    }

    for (i = 0; i < (uint8_t)sizeof(channels_5g); i++) {
        chan.hw_value_le = mt7921_cpu_to_le16(channels_5g[i]);
        chan.flags_le = mt7921_cpu_to_le32(0);
        memcpy(req + pos, &chan, sizeof(chan));
        pos += sizeof(chan);
        hdr.n_5ch++;
    }

    memcpy(req, &hdr, sizeof(hdr));

    return mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_SET_CHAN_DOMAIN, req,
                               pos, false, NULL, 0);
}

static int mt7921_mcu_set_scan_channel(mt7921_priv_t *priv, uint8_t band,
                                       uint8_t channel, uint8_t switch_reason,
                                       bool wait_resp) {
    struct {
        uint8_t control_ch;
        uint8_t center_ch;
        uint8_t bw;
        uint8_t tx_streams_num;
        uint8_t rx_streams;
        uint8_t switch_reason;
        uint8_t band_idx;
        uint8_t center_ch2;
        uint16_t cac_case_le;
        uint8_t channel_band;
        uint8_t rsv0;
        uint32_t outband_freq_le;
        uint8_t txpower_drop;
        uint8_t ap_bw;
        uint8_t ap_center_ch;
        uint8_t rsv1[57];
    } __attribute__((packed)) req;
    uint8_t rx_mask;

    memset(&req, 0, sizeof(req));

    req.control_ch = channel;
    req.center_ch = channel;
    req.bw = 0;

    rx_mask = priv->antenna_mask ? priv->antenna_mask : 1U;
    req.tx_streams_num = mt7921_popcount8(rx_mask);
    if (!req.tx_streams_num) {
        req.tx_streams_num = 1;
    }
    req.rx_streams = rx_mask;

    req.switch_reason = switch_reason;
    req.band_idx = 0;
    req.channel_band = band;

    return mt7921_mcu_send_msg(priv, MT7921_MCU_EXT_CMD_SET_RX_PATH, &req,
                               sizeof(req), wait_resp, NULL, 0);
}

static int mt7921_mcu_set_rx_path(mt7921_priv_t *priv) {
    return mt7921_mcu_set_scan_channel(priv, 0, 1, MT7921_CH_SWITCH_NORMAL,
                                       true);
}

static int mt7921_mcu_set_rxfilter(mt7921_priv_t *priv, uint32_t fif,
                                   uint8_t bit_op, uint32_t bit_map) {
    struct {
        uint8_t rsv[4];
        uint8_t mode;
        uint8_t rsv2[3];
        uint32_t fif_le;
        uint32_t bit_map_le;
        uint8_t bit_op;
        uint8_t pad[51];
    } __attribute__((packed)) data;

    memset(&data, 0, sizeof(data));
    data.mode = fif ? 1U : 2U;
    data.fif_le = mt7921_cpu_to_le32(fif);
    data.bit_map_le = mt7921_cpu_to_le32(bit_map);
    data.bit_op = bit_op;

    return mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_SET_RX_FILTER, &data,
                               sizeof(data), false, NULL, 0);
}

static int mt7921_mcu_runtime_start(mt7921_priv_t *priv) {
    int ret;

    ret = mt7921_mcu_set_eeprom(priv);
    if (ret) {
        printk("mt7921: set_eeprom failed: %d\n", ret);
        return ret;
    }
    printk("mt7921: set_eeprom ok\n");

    ret = mt7921_mcu_set_mac_enable(priv, 0, true);
    if (ret) {
        printk("mt7921: set_mac_enable failed: %d\n", ret);
        return ret;
    }
    printk("mt7921: set_mac_enable ok\n");

    ret = mt7921_mcu_set_channel_domain(priv);
    if (ret) {
        printk("mt7921: set_channel_domain failed: %d\n", ret);
        return ret;
    }
    printk("mt7921: set_channel_domain ok\n");

    ret = mt7921_mcu_set_rx_path(priv);
    if (ret) {
        printk("mt7921: set_rx_path failed: %d\n", ret);
        return ret;
    }
    printk("mt7921: set_rx_path ok\n");

    ret = mt7921_mcu_set_rxfilter(priv, 0, MT7921_RX_FILTER_BIT_CLR,
                                  MT7921_WF_RFCR_DROP_OTHER_BEACON);
    if (ret) {
        printk("mt7921: set_rxfilter failed: %d\n", ret);
        return ret;
    }
    printk("mt7921: set_rxfilter ok\n");

    return 0;
}

static int mt7921_load_clc(mt7921_priv_t *priv) {
    (void)priv;
    return 0;
}

static int mt7921_get_patch_firmware(mt7921_priv_t *priv, uint8_t **data,
                                     size_t *size) {
    (void)priv;
    vfs_node_t node = vfs_open("/lib/firmware/" MT7921_ROM_PATCH, 0);
    if (!node) {
        printk("Failed to open patch firmware file\n");
        return -ENOENT;
    }
    printk("Patch firmware size: %d bytes\n", node->size);
    uint8_t *buf = malloc(node->size);
    if (!buf)
        return -ENOMEM;

    vfs_read(node, buf, 0, node->size);
    *data = buf;
    *size = node->size;
    return 0;
}

static int mt7921_get_ram_firmware(mt7921_priv_t *priv, uint8_t **data,
                                   size_t *size) {
    (void)priv;
    vfs_node_t node = vfs_open("/lib/firmware/" MT7921_FIRMWARE_WM, 0);
    if (!node) {
        printk("Failed to open ram firmware file\n");
        return -ENOENT;
    }
    printk("RAM firmware size: %d bytes\n", node->size);
    uint8_t *buf = malloc(node->size);
    if (!buf)
        return -ENOMEM;

    vfs_read(node, buf, 0, node->size);
    *data = buf;
    *size = node->size;
    return 0;
}

static int mt7921_send_patch_firmware(mt7921_priv_t *priv, uint8_t *data,
                                      size_t size) {
    const struct mt7921_patch_hdr *hdr = (const struct mt7921_patch_hdr *)data;
    int sem;
    int ret = 0;

    if (!data || size < sizeof(*hdr)) {
        return -EINVAL;
    }

    sem = mt7921_mcu_patch_sem_ctrl(priv, true);
    if (sem < 0) {
        return sem;
    }
    if (sem == MT7921_PATCH_IS_DL) {
        return 0;
    }
    if (sem != MT7921_PATCH_NOT_DL_SEM_SUCCESS) {
        return -EAGAIN;
    }

    uint32_t n_region = mt7921_be32_to_cpu(hdr->desc.n_region_be);
    if (size < sizeof(*hdr) + n_region * sizeof(struct mt7921_patch_sec)) {
        ret = -EINVAL;
        goto out;
    }

    for (uint32_t i = 0; i < n_region; i++) {
        const struct mt7921_patch_sec *sec =
            (const struct mt7921_patch_sec *)(data + sizeof(*hdr) +
                                              i * sizeof(
                                                      struct mt7921_patch_sec));
        uint32_t type = mt7921_be32_to_cpu(sec->type_be);
        uint32_t offs = mt7921_be32_to_cpu(sec->offs_be);
        uint32_t sec_size = mt7921_be32_to_cpu(sec->size_be);
        uint32_t addr = mt7921_be32_to_cpu(sec->info.addr_be);
        uint32_t len = mt7921_be32_to_cpu(sec->info.len_be);
        uint32_t sec_info = mt7921_be32_to_cpu(sec->info.sec_key_idx_be);
        uint32_t mode = mt7921_patch_get_data_mode(sec_info);
        uint32_t copy_len = len;

        if ((type & MT7921_PATCH_SEC_TYPE_MASK) != MT7921_PATCH_SEC_TYPE_INFO) {
            ret = -EINVAL;
            goto out;
        }
        if (offs >= size || sec_size > size - offs) {
            ret = -EINVAL;
            goto out;
        }
        if (copy_len > sec_size) {
            copy_len = sec_size;
        }

        ret = mt7921_mcu_init_download(priv, addr, copy_len, mode);
        if (ret) {
            goto out;
        }

        ret = mt7921_mcu_send_scatter(priv, data + offs, copy_len);
        if (ret) {
            goto out;
        }
    }

    ret = mt7921_mcu_start_patch(priv);
    if (ret) {
        goto out;
    }

out:
    sem = mt7921_mcu_patch_sem_ctrl(priv, false);
    if (sem != MT7921_PATCH_REL_SEM_SUCCESS) {
        return -EAGAIN;
    }

    return ret;
}

static int mt7921_send_ram_firmware(mt7921_priv_t *priv, uint8_t *data,
                                    size_t size) {
    if (!data || size < sizeof(struct mt7921_fw_trailer)) {
        return -EINVAL;
    }

    const struct mt7921_fw_trailer *trailer =
        (const struct mt7921_fw_trailer *)(data + size - sizeof(*trailer));
    size_t region_table_size =
        (size_t)trailer->n_region * sizeof(struct mt7921_fw_region);
    if (size < sizeof(*trailer) + region_table_size) {
        return -EINVAL;
    }

    size_t payload_off = 0;
    uint32_t override = 0;
    uint32_t option = 0;
    const struct mt7921_fw_region *region =
        (const struct mt7921_fw_region *)((const uint8_t *)trailer -
                                          region_table_size);

    for (uint8_t i = 0; i < trailer->n_region; i++) {
        uint32_t addr = mt7921_le32_to_cpu(region[i].addr_le);
        uint32_t len = mt7921_le32_to_cpu(region[i].len_le);
        uint32_t mode = mt7921_ram_get_data_mode(region[i].feature_set);
        int ret;

        if (len > size || payload_off > size - len) {
            return -EINVAL;
        }

        if (region[i].feature_set & MT7921_FW_FEATURE_NON_DL) {
            payload_off += len;
            continue;
        }

        if (region[i].feature_set & MT7921_FW_FEATURE_OVERRIDE_ADDR) {
            override = addr;
        }

        ret = mt7921_mcu_init_download(priv, addr, len, mode);
        if (ret) {
            return ret;
        }

        ret = mt7921_mcu_send_scatter(priv, data + payload_off, len);
        if (ret) {
            return ret;
        }
        payload_off += len;
    }

    if (override) {
        option |= MT7921_FW_START_OVERRIDE;
    }

    return mt7921_mcu_start_firmware(priv, override, option);
}

static int mt7921_wait_fw_ready(mt7921_priv_t *priv) {
    if (!mt7921_wait(priv, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_N9_RDY_VALUE,
                     MT_TOP_MISC2_FW_N9_RDY_VALUE, 1500, 1)) {
        printk("Timeout for initializing firmware\n");
        return -ETIMEDOUT;
    }

    return 0;
}

static int mt7921_run_firmware(mt7921_priv_t *priv) {
    uint8_t *patch_data = NULL;
    uint8_t *ram_data = NULL;
    size_t patch_size = 0;
    size_t ram_size = 0;
    int ret;

    ret = mt7921_get_patch_firmware(priv, &patch_data, &patch_size);
    if (ret) {
        printk("Failed to get patch firmware\n");
        goto out;
    }

    ret = mt7921_send_patch_firmware(priv, patch_data, patch_size);
    if (ret) {
        printk("Failed to send patch firmware\n");
        goto out;
    }

    ret = mt7921_get_ram_firmware(priv, &ram_data, &ram_size);
    if (ret) {
        printk("Failed to get ram firmware\n");
        goto out;
    }

    ret = mt7921_send_ram_firmware(priv, ram_data, ram_size);
    if (ret) {
        printk("Failed to send ram firmware\n");
        goto out;
    }

    ret = mt7921_wait_fw_ready(priv);
    if (ret) {
        goto out;
    }

    ret = mt7921_mcu_get_nic_capability(priv);
    if (ret) {
        printk("Failed to get NIC capability\n");
        goto out;
    }

    ret = mt7921_load_clc(priv);
    if (ret) {
        printk("Failed to load CLC\n");
        goto out;
    }

    ret = mt7921_mcu_runtime_start(priv);
    if (ret) {
        printk("Failed to start runtime MAC/channel/rx path\n");
        goto out;
    }

    ret = mt7921_mcu_fw_log_2_host(priv, 1);
    if (ret) {
        printk("Failed to enable FW log to host\n");
        goto out;
    }

out:
    free(patch_data);
    free(ram_data);
    return ret;
}

uint32_t mt7921_read_uhw_reg(mt7921_priv_t *priv, uint32_t addr) {
    mutex_lock(&priv->reg_lock);
    struct usb_ctrlrequest req;
    req.bRequest = MT_VEND_DEV_MODE;
    req.bRequestType = USB_DIR_IN | MT_USB_TYPE_UHW_VENDOR;
    req.wValue = addr >> 16;
    req.wIndex = addr & 0xffff;
    req.wLength = sizeof(uint32_t);
    uint32_t ret = 0;
    usb_send_default_control(priv->usbdev->defpipe, &req, &ret);
    mutex_unlock(&priv->reg_lock);
    return ret;
}

void mt7921_write_uhw_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t val) {
    mutex_lock(&priv->reg_lock);
    struct usb_ctrlrequest req;
    req.bRequest = MT_VEND_WRITE;
    req.bRequestType = USB_DIR_OUT | MT_USB_TYPE_UHW_VENDOR;
    req.wValue = addr >> 16;
    req.wIndex = addr & 0xffff;
    req.wLength = sizeof(uint32_t);
    usb_send_default_control(priv->usbdev->defpipe, &req, &val);
    mutex_unlock(&priv->reg_lock);
}

uint32_t mt7921_read_reg(mt7921_priv_t *priv, uint32_t addr) {
    mutex_lock(&priv->reg_lock);
    struct usb_ctrlrequest req;
    req.bRequest = MT_VEND_READ_EXT;
    req.bRequestType = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE;
    req.wValue = addr >> 16;
    req.wIndex = addr & 0xffff;
    req.wLength = sizeof(uint32_t);
    uint32_t ret = 0;
    usb_send_default_control(priv->usbdev->defpipe, &req, &ret);
    mutex_unlock(&priv->reg_lock);
    return ret;
}

void mt7921_write_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t val) {
    mutex_lock(&priv->reg_lock);
    struct usb_ctrlrequest req;
    req.bRequest = MT_VEND_WRITE_EXT;
    req.bRequestType = USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE;
    req.wValue = addr >> 16;
    req.wIndex = addr & 0xffff;
    req.wLength = sizeof(uint32_t);
    usb_send_default_control(priv->usbdev->defpipe, &req, &val);
    mutex_unlock(&priv->reg_lock);
}

int mt7921_wfsys_reset(mt7921_priv_t *priv) {
    mt7921_epctl_rst_opt(priv, false);

    uint32_t val = mt7921_read_uhw_reg(priv, 0x70002000 + 0x600);
    val |= (1 << 0);
    mt7921_write_uhw_reg(priv, 0x70002000 + 0x600, val);

    delay_us(20);
    val = mt7921_read_uhw_reg(priv, 0x70002000 + 0x600);
    val &= ~(1 << 0);
    mt7921_write_uhw_reg(priv, 0x70002000 + 0x600, val);

    mt7921_write_uhw_reg(priv, 0x74000000 + 0xa24, 0);
    int i;
    for (i = 0; i < 2; i++) {
        uint32_t val = mt7921_read_uhw_reg(priv, 0x74000000 + 0xa20);
        if (val & (1 << 22)) {
            break;
        }
        delay_us(100 * 1000);
    }

    if (i == 2) {
        return -ETIMEDOUT;
    }

    return 0;
}

int mt76u_vendor_request(mt7921_priv_t *dev, uint8_t req, uint8_t req_type,
                         uint16_t val, uint16_t offset, void *buf, size_t len) {
    mutex_lock(&dev->reg_lock);
    struct usb_ctrlrequest ctrlreq;
    ctrlreq.bRequest = req;
    ctrlreq.bRequestType = req_type;
    ctrlreq.wValue = val;
    ctrlreq.wIndex = offset;
    ctrlreq.wLength = len;
    int ret = usb_send_default_control(dev->usbdev->defpipe, &ctrlreq, buf);
    mutex_unlock(&dev->reg_lock);
    return ret;
}

bool mt7921_wait(mt7921_priv_t *priv, uint32_t addr, uint32_t mask,
                 uint32_t val, uint64_t timeout_ms, uint64_t tick) {
    uint64_t start = nano_time();
    while ((nano_time() - start) < timeout_ms * 1000000ULL) {
        uint32_t reg_val = mt7921_read_reg(priv, addr);
        if ((reg_val & mask) == val) {
            return true;
        }
        delay_us(tick * 2000);
    }
    printk("Timeout waiting for reg 0x%08x to be 0x%08x (mask 0x%08x)\n", addr,
           val, mask);
    return false;
}

void mt7921_set_tx_context(mt7921_priv_t *priv, uint16_t wlan_idx,
                           uint8_t own_mac_idx) {
    if (!priv) {
        return;
    }

    priv->tx_wlan_idx = (uint16_t)(wlan_idx & 0x03ffU);
    priv->tx_own_mac_idx = (uint8_t)(own_mac_idx & 0x3fU);
}

int mt7921_mcu_power_on(mt7921_priv_t *priv) {
    int ret = mt76u_vendor_request(
        priv, MT_VEND_POWER_ON,
        USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0, 0x1, NULL, 0);

    if (ret)
        return ret;

    if (!mt7921_wait(priv, 0x7c0600f0, (1 << 0), (1 << 0), 500, 10)) {
        printk("Failed to power on MCU\n");
        return -ETIMEDOUT;
    }

    return ret;
}

static int mt7921_usb_init_pipes(mt7921_priv_t *priv,
                                 struct usbdevice_a_interface *iface) {
    uint8_t *p = (uint8_t *)iface->iface + iface->iface->bLength;
    int scanned = 0;
    int in_eps = 0;
    int out_eps = 0;
    int i;

    memset(priv->in_pipes, 0, sizeof(priv->in_pipes));
    memset(priv->out_pipes, 0, sizeof(priv->out_pipes));

    struct usb_super_speed_endpoint_descriptor *ss_desc =
        usb_find_ss_desc(iface);

    while (scanned < iface->iface->bNumEndpoints) {
        struct usb_endpoint_descriptor *ep =
            (struct usb_endpoint_descriptor *)p;

        if (!ep->bLength) {
            break;
        }
        if (ep->bDescriptorType == USB_DT_INTERFACE) {
            break;
        }
        if (ep->bDescriptorType == USB_DT_ENDPOINT) {
            if ((ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
                USB_ENDPOINT_XFER_BULK) {
                if (((ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK) ==
                     USB_DIR_IN) &&
                    in_eps < __MT_EP_IN_MAX) {
                    priv->in_pipes[in_eps] =
                        usb_alloc_pipe(priv->usbdev, ep, ss_desc);
                    printk("mt7921: enum IN ep idx=%d addr=0x%02x\n", in_eps,
                           ep->bEndpointAddress);
                    in_eps++;
                } else if (((ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK) ==
                            USB_DIR_OUT) &&
                           out_eps < __MT_EP_OUT_MAX) {
                    priv->out_pipes[out_eps] =
                        usb_alloc_pipe(priv->usbdev, ep, ss_desc);
                    printk("mt7921: enum OUT ep idx=%d addr=0x%02x\n", out_eps,
                           ep->bEndpointAddress);
                    out_eps++;
                }
            }
            scanned++;
        }

        p += ep->bLength;
    }

    printk("mt7921: pipe map data_in=%u mcu_in=%u mcu_out=%u data_out=%u\n",
           MT7921_PIPE_DATA_IN(priv) ? MT7921_PIPE_DATA_IN(priv)->ep : 0xff,
           MT7921_PIPE_MCU_IN(priv) ? MT7921_PIPE_MCU_IN(priv)->ep : 0xff,
           MT7921_PIPE_MCU_OUT(priv) ? MT7921_PIPE_MCU_OUT(priv)->ep : 0xff,
           MT7921_PIPE_DATA_OUT(priv) ? MT7921_PIPE_DATA_OUT(priv)->ep : 0xff);

    if (!MT7921_PIPE_DATA_IN(priv) || !MT7921_PIPE_MCU_IN(priv) ||
        !MT7921_PIPE_MCU_OUT(priv) || !MT7921_PIPE_DATA_OUT(priv)) {
        for (i = 0; i < __MT_EP_IN_MAX; i++) {
            if (priv->in_pipes[i]) {
                usb_free_pipe(priv->usbdev, priv->in_pipes[i]);
                priv->in_pipes[i] = NULL;
            }
        }
        for (i = 0; i < __MT_EP_OUT_MAX; i++) {
            if (priv->out_pipes[i]) {
                usb_free_pipe(priv->usbdev, priv->out_pipes[i]);
                priv->out_pipes[i] = NULL;
            }
        }
        return -ENODEV;
    }

    return 0;
}

static void mt7921_usb_deinit_pipes(mt7921_priv_t *priv) {
    int i;

    if (!priv) {
        return;
    }

    for (i = 0; i < __MT_EP_IN_MAX; i++) {
        if (priv->in_pipes[i]) {
            usb_free_pipe(priv->usbdev, priv->in_pipes[i]);
            priv->in_pipes[i] = NULL;
        }
    }
    for (i = 0; i < __MT_EP_OUT_MAX; i++) {
        if (priv->out_pipes[i]) {
            usb_free_pipe(priv->usbdev, priv->out_pipes[i]);
            priv->out_pipes[i] = NULL;
        }
    }
}

static int mt7921_register_rtnl_dev(mt7921_priv_t *priv) {
    struct net_device *rdev = NULL;
    char name[IFNAMSIZ];
    int i;
    int ret;

    if (!priv) {
        return -EINVAL;
    }

    for (i = 0; i < 8; i++) {
        memset(name, 0, sizeof(name));
        snprintf(name, sizeof(name), "wlan%d", i);
        if (!rtnl_dev_get_by_name(name)) {
            rdev = rtnl_dev_alloc(name, ARPHRD_ETHER);
            if (rdev) {
                break;
            }
        }
    }

    if (!rdev) {
        return -ENOMEM;
    }

    memcpy(rdev->addr, priv->macaddr, 6);
    memset(rdev->broadcast, 0xff, 6);
    rdev->addr_len = 6;
    rdev->mtu = 1500;

    ret = rtnl_dev_register(rdev);
    if (ret < 0) {
        return ret;
    }

    rtnl_dev_set_wireless_handler(rdev, priv, mt7921_rtnl_wireless_cmd);
    rtnl_notify_link(rdev, RTM_NEWLINK);
    priv->rtnl_dev = rdev;

    return 0;
}

int mt7921_probe(struct usbdevice_s *usbdev,
                 struct usbdevice_a_interface *iface) {
    mt7921_priv_t *priv = malloc(sizeof(mt7921_priv_t));
    if (!priv) {
        return -ENOENT;
    }
    memset(priv, 0, sizeof(*priv));
    mutex_init(&priv->reg_lock);
    mutex_init(&priv->io_lock);
    priv->usbdev = usbdev;
    priv->mcu_seq = 0;
    priv->scan_seq = 0;
    priv->tx_wlan_idx = 0;
    priv->tx_own_mac_idx = 0;
    priv->mgmt_seq = 0;

    int ret = 0;

    ret = mt7921_usb_init_pipes(priv, iface);
    if (ret) {
        printk("Failed to init USB bulk pipes\n");
        goto err;
    }

    if (mt76_get_field(priv, 0x7c0600f0, MT_TOP_MISC2_FW_N9_RDY)) {
        ret = mt7921_wfsys_reset(priv);
        if (ret) {
            goto err;
        }
    }

    ret = mt7921_mcu_power_on(priv);
    if (ret) {
        printk("Failed to power on MCU\n");
        goto err;
    }

    ret = mt7921_dma_init(priv, false);
    if (ret) {
        printk("Failed to init DMA\n");
        goto err;
    }

    mt7921_set_reg_bits(priv, MT_UDMA_TX_QSEL, MT_FW_DL_EN);
    ret = mt7921_run_firmware(priv);
    mt7921_clear_reg_bits(priv, MT_UDMA_TX_QSEL, MT_FW_DL_EN);
    if (ret) {
        printk("Failed to run firmware\n");
        goto err;
    }

    ret = ieee80211_netif_init(&priv->wlan_if, priv, mt7921_tx_raw,
                               mt7921_rx_raw, priv->macaddr);
    if (ret) {
        printk("Failed to init ieee80211 netif\n");
        goto err;
    }

    ieee80211_ctx_clear_bssid(&priv->wlan_if.ctx);
    regist_netdev(priv, priv->macaddr, 1500, mt7921_netdev_send,
                  mt7921_netdev_recv);

    ret = mt7921_register_rtnl_dev(priv);
    if (ret) {
        printk("Failed to register rtnl device\n");
        goto err;
    }

    printk("mt7921 initialized successfully\n");

    usbdev->desc = priv;

    return 0;

err:
    mt7921_usb_deinit_pipes(priv);
    free(priv);
    return ret;
}

int mt7921_remove(struct usbdevice_s *usbdev) {
    mt7921_priv_t *priv;

    if (!usbdev) {
        return 0;
    }

    priv = usbdev->desc;
    if (!priv) {
        return 0;
    }

    if (priv->rtnl_dev) {
        rtnl_notify_link(priv->rtnl_dev, RTM_DELLINK);
        rtnl_dev_unregister(priv->rtnl_dev);
        priv->rtnl_dev = NULL;
    }

    mt7921_usb_deinit_pipes(priv);
    usbdev->desc = NULL;
    free(priv);

    return 0;
}

usb_driver_t mt7921_general_driver = {
    .vendorid = 0x0e8d,
    .productid = 0x7961,
    .probe = mt7921_probe,
    .remove = mt7921_remove,
};
usb_driver_t mt7921_cf_952ax_driver = {
    .vendorid = 0x3574,
    .productid = 0x6211,
    .probe = mt7921_probe,
    .remove = mt7921_remove,
};
usb_driver_t mt7921_ax8000_axe3000_driver = {
    .vendorid = 0x0846,
    .productid = 0x9060,
    .probe = mt7921_probe,
    .remove = mt7921_remove,
};
usb_driver_t mt7921_a7500_driver = {
    .vendorid = 0x0846,
    .productid = 0x9065,
    .probe = mt7921_probe,
    .remove = mt7921_remove,
};
usb_driver_t mt7921_txe50uh_driver = {
    .vendorid = 0x35bc,
    .productid = 0x0107,
    .probe = mt7921_probe,
    .remove = mt7921_remove,
};

__attribute__((visibility("default"))) int dlmain() {
    regist_usb_driver(&mt7921_general_driver);
    regist_usb_driver(&mt7921_cf_952ax_driver);
    regist_usb_driver(&mt7921_ax8000_axe3000_driver);
    regist_usb_driver(&mt7921_a7500_driver);
    regist_usb_driver(&mt7921_txe50uh_driver);

    return 0;
}
