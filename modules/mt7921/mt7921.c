#include "mt7921.h"

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

#define MT7921_MCU_CMD_TARGET_ADDRESS_LEN_REQ MT7921_MCU_CMD(0x01)
#define MT7921_MCU_CMD_FW_START_REQ MT7921_MCU_CMD(0x02)
#define MT7921_MCU_CMD_PATCH_START_REQ MT7921_MCU_CMD(0x05)
#define MT7921_MCU_CMD_PATCH_FINISH_REQ MT7921_MCU_CMD(0x07)
#define MT7921_MCU_CMD_PATCH_SEM_CONTROL MT7921_MCU_CMD(0x10)
#define MT7921_MCU_CMD_FW_SCATTER MT7921_MCU_CMD(0xee)

#define MT7921_MCU_CE_CMD_GET_NIC_CAPAB MT7921_MCU_CE_CMD(0x8a)
#define MT7921_MCU_CE_CMD_FWLOG_2_HOST MT7921_MCU_CE_CMD(0xc5)

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

#define MT7921_NIC_CAP_MAC_ADDR 7
#define MT7921_NIC_CAP_PHY 8
#define MT7921_NIC_CAP_6G 0x18

#define MT7921_HW_PATH_2G_BIT (1U << 0)
#define MT7921_HW_PATH_5G_BIT (1U << 1)

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

static uint32_t mt7921_be32_to_cpu(uint32_t v) {
    return ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) |
           ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);
}

static uint32_t mt7921_le32_to_cpu(uint32_t v) { return v; }
static uint16_t mt7921_le16_to_cpu(uint16_t v) { return v; }

static size_t mt7921_min_size(size_t a, size_t b) {
    if (a < b) {
        return a;
    }
    return b;
}

static int mt7921_usb_bulk_send(mt7921_priv_t *priv, struct usb_pipe *pipe,
                                uint8_t *payload, size_t payload_len) {
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

static int mt7921_mcu_send_msg(mt7921_priv_t *priv, uint32_t cmd, void *req,
                               size_t req_len, bool wait_resp, void *resp,
                               size_t resp_len) {
    struct mt7921_mcu_txd txd;
    uint8_t tx_buf[512];
    uint8_t rx_buf[MT7921_MCU_RX_BUF_SIZE];
    struct usb_pipe *out_pipe;
    uint8_t seq;
    uint8_t cmd_id = (uint8_t)(cmd & MT7921_MCU_CMD_FIELD_ID_MASK);
    uint8_t ext_id = (uint8_t)((cmd & MT7921_MCU_CMD_FIELD_EXT_ID_MASK) >> 8);
    int ret;
    uint8_t status;

    if (!priv->mcu_in || !priv->mcu_out) {
        return -ENODEV;
    }

    if (cmd == MT7921_MCU_CMD_FW_SCATTER) {
        out_pipe = priv->fwdl_out ? priv->fwdl_out : priv->mcu_out;
        ret = mt7921_usb_bulk_send(priv, out_pipe, req, req_len);
        if (ret) {
            return ret;
        }
    } else {
        if (sizeof(txd) + req_len > sizeof(tx_buf)) {
            return -E2BIG;
        }

        memset(&txd, 0, sizeof(txd));
        memset(tx_buf, 0, sizeof(tx_buf));

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

        ret = mt7921_usb_bulk_send(priv, priv->mcu_out, tx_buf,
                                   sizeof(txd) + req_len);
        if (ret) {
            return ret;
        }
    }

    if (!wait_resp) {
        return 0;
    }

    memset(rx_buf, 0, sizeof(rx_buf));
    ret = usb_send_bulk(priv->mcu_in, USB_DIR_IN, rx_buf, sizeof(rx_buf));
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

static struct usb_endpoint_descriptor *
mt7921_find_nth_bulk_out(struct usbdevice_a_interface *iface, int nth) {
    uint8_t *p = (uint8_t *)iface->iface + iface->iface->bLength;
    int seen = 0;
    int scanned = 0;
    int max_scan = 64;

    while (max_scan-- > 0 && scanned < iface->iface->bNumEndpoints) {
        struct usb_endpoint_descriptor *ep =
            (struct usb_endpoint_descriptor *)p;

        if (!ep->bLength) {
            break;
        }
        if (ep->bDescriptorType == USB_DT_INTERFACE) {
            break;
        }
        if (ep->bDescriptorType == USB_DT_ENDPOINT) {
            scanned++;
            if ((ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
                    USB_ENDPOINT_XFER_BULK &&
                (ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_OUT) {
                if (seen == nth) {
                    return ep;
                }
                seen++;
            }
        }

        p += ep->bLength;
    }

    return NULL;
}

static int mt7921_usb_init_pipes(mt7921_priv_t *priv,
                                 struct usbdevice_a_interface *iface) {
    struct usb_endpoint_descriptor *in_desc;
    struct usb_endpoint_descriptor *out0_desc;
    struct usb_endpoint_descriptor *out1_desc;

    in_desc = usb_find_desc(iface, USB_ENDPOINT_XFER_BULK, USB_DIR_IN);
    out0_desc = mt7921_find_nth_bulk_out(iface, 0);
    out1_desc = mt7921_find_nth_bulk_out(iface, 1);
    if (!out1_desc) {
        out1_desc = out0_desc;
    }

    if (!in_desc || !out0_desc) {
        return -ENODEV;
    }

    priv->mcu_in = usb_alloc_pipe(priv->usbdev, in_desc);
    priv->mcu_out = usb_alloc_pipe(priv->usbdev, out0_desc);
    if (!priv->mcu_in || !priv->mcu_out) {
        return -ENOMEM;
    }

    if (out1_desc == out0_desc) {
        priv->fwdl_out = priv->mcu_out;
    } else {
        priv->fwdl_out = usb_alloc_pipe(priv->usbdev, out1_desc);
        if (!priv->fwdl_out) {
            return -ENOMEM;
        }
    }

    return 0;
}

static void mt7921_usb_deinit_pipes(mt7921_priv_t *priv) {
    if (!priv) {
        return;
    }

    usb_free_pipe(priv->usbdev, priv->mcu_in);
    if (priv->fwdl_out && priv->fwdl_out != priv->mcu_out) {
        usb_free_pipe(priv->usbdev, priv->fwdl_out);
    }
    usb_free_pipe(priv->usbdev, priv->mcu_out);

    priv->mcu_in = NULL;
    priv->mcu_out = NULL;
    priv->fwdl_out = NULL;
}

int mt7921_probe(struct usbdevice_s *usbdev,
                 struct usbdevice_a_interface *iface) {
    mt7921_priv_t *priv = malloc(sizeof(mt7921_priv_t));
    if (!priv) {
        return -ENOENT;
    }
    memset(priv, 0, sizeof(*priv));
    mutex_init(&priv->reg_lock);
    priv->usbdev = usbdev;
    priv->mcu_seq = 0;

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

    printk("MT7921 initialized successfully\n");

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
