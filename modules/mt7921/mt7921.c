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

static uint32_t mt7921_be32_to_cpu(uint32_t v) {
    return ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) |
           ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);
}

static uint32_t mt7921_le32_to_cpu(uint32_t v) { return v; }

static size_t mt7921_min_size(size_t a, size_t b) {
    if (a < b) {
        return a;
    }
    return b;
}

static int mt7921_get_patch_firmware(mt7921_priv_t *priv, uint8_t **data,
                                     size_t *size) {
    (void)priv;
    vfs_node_t node = vfs_open("/lib/firmware/" MT7921_ROM_PATCH, 0);
    uint8_t *buf = alloc_frames_bytes(node->size);
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
    uint8_t *buf = alloc_frames_bytes(node->size);
    if (!buf)
        return -ENOMEM;

    vfs_read(node, buf, 0, node->size);
    *data = buf;
    *size = node->size;
    return 0;
}

static int mt7921_write_firmware_block(mt7921_priv_t *priv, uint32_t addr,
                                       uint8_t *data, size_t len) {
    size_t offset = 0;
    uint8_t tmp[MT7921_VENDOR_COPY_CHUNK];

    while (offset < len) {
        size_t chunk =
            mt7921_min_size((size_t)MT7921_VENDOR_COPY_CHUNK, len - offset);
        size_t padded = (chunk + 3U) & ~3U;

        memcpy(tmp, data + offset, chunk);
        if (padded > chunk) {
            memset(tmp + chunk, 0, padded - chunk);
        }

        if (mt76u_vendor_request(
                priv, MT_VEND_WRITE_EXT,
                USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
                (uint16_t)((addr + offset) >> 16),
                (uint16_t)((addr + offset) & 0xffffU), tmp, padded)) {
            return -EIO;
        }

        offset += chunk;
    }

    return 0;
}

static int mt7921_send_patch_firmware(mt7921_priv_t *priv, uint8_t *data,
                                      size_t size) {
    const struct mt7921_patch_hdr *hdr = (const struct mt7921_patch_hdr *)data;
    uint32_t n_region;
    uint32_t i;

    if (!data || size < sizeof(*hdr)) {
        return -EINVAL;
    }

    n_region = mt7921_be32_to_cpu(hdr->desc.n_region_be);
    if (size < sizeof(*hdr) + n_region * sizeof(struct mt7921_patch_sec)) {
        return -EINVAL;
    }

    for (i = 0; i < n_region; i++) {
        const struct mt7921_patch_sec *sec =
            (const struct mt7921_patch_sec *)(data + sizeof(*hdr) +
                                              i * sizeof(
                                                      struct mt7921_patch_sec));
        uint32_t type = mt7921_be32_to_cpu(sec->type_be);
        uint32_t offs = mt7921_be32_to_cpu(sec->offs_be);
        uint32_t sec_size = mt7921_be32_to_cpu(sec->size_be);
        uint32_t addr = mt7921_be32_to_cpu(sec->info.addr_be);
        uint32_t len = mt7921_be32_to_cpu(sec->info.len_be);
        uint32_t copy_len = len;
        int ret;

        if ((type & MT7921_PATCH_SEC_TYPE_MASK) != MT7921_PATCH_SEC_TYPE_INFO) {
            return -EINVAL;
        }
        if (offs >= size || sec_size > size - offs) {
            return -EINVAL;
        }
        if (copy_len > sec_size) {
            copy_len = sec_size;
        }

        ret = mt7921_write_firmware_block(priv, addr, data + offs, copy_len);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

static int mt7921_send_ram_firmware(mt7921_priv_t *priv, uint8_t *data,
                                    size_t size) {
    const struct mt7921_fw_trailer *trailer;
    size_t region_table_size;
    const struct mt7921_fw_region *region;
    size_t payload_off = 0;
    uint8_t i;

    if (!data || size < sizeof(struct mt7921_fw_trailer)) {
        return -EINVAL;
    }

    trailer =
        (const struct mt7921_fw_trailer *)(data + size - sizeof(*trailer));
    region_table_size =
        (size_t)trailer->n_region * sizeof(struct mt7921_fw_region);
    if (size < sizeof(*trailer) + region_table_size) {
        return -EINVAL;
    }

    region = (const struct mt7921_fw_region *)((const uint8_t *)trailer -
                                               region_table_size);

    for (i = 0; i < trailer->n_region; i++) {
        uint32_t addr = mt7921_le32_to_cpu(region[i].addr_le);
        uint32_t len = mt7921_le32_to_cpu(region[i].len_le);
        int ret;

        if (len > size || payload_off > size - len) {
            return -EINVAL;
        }

        if (region[i].feature_set & MT7921_FW_FEATURE_NON_DL) {
            payload_off += len;
            continue;
        }

        ret = mt7921_write_firmware_block(priv, addr, data + payload_off, len);
        if (ret) {
            return ret;
        }
        payload_off += len;
    }

    return 0;
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

    mt7921_set_reg_bits(priv, MT_UDMA_TX_QSEL, MT_FW_DL_EN);

    ret = mt7921_get_patch_firmware(priv, &patch_data, &patch_size);
    if (ret) {
        goto out;
    }

    ret = mt7921_send_patch_firmware(priv, patch_data, patch_size);
    if (ret) {
        goto out;
    }

    ret = mt7921_get_ram_firmware(priv, &ram_data, &ram_size);
    if (ret) {
        goto out;
    }

    ret = mt7921_send_ram_firmware(priv, ram_data, ram_size);
    if (ret) {
        goto out;
    }

    ret = mt7921_wait_fw_ready(priv);

out:
    free_frames_bytes(patch_data, patch_size);
    free_frames_bytes(ram_data, ram_size);

    mt7921_clear_reg_bits(priv, MT_UDMA_TX_QSEL, MT_FW_DL_EN);
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
    req.bRequest = MT_VEND_WRITE;
    req.bRequestType = USB_DIR_OUT | MT_USB_TYPE_UHW_VENDOR;
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
    req.bRequest = MT_VEND_READ_EXT;
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
    while ((nano_time() - start) < timeout_ms * 1000ULL) {
        uint32_t reg_val = mt7921_read_reg(priv, addr);
        if ((reg_val & mask) == val) {
            return true;
        }
        delay_us(tick * 2000);
    }
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

int mt7921_probe(struct usbdevice_s *usbdev,
                 struct usbdevice_a_interface *iface) {
    mt7921_priv_t *priv = malloc(sizeof(mt7921_priv_t));
    if (!priv) {
        return -ENOENT;
    }
    mutex_init(&priv->reg_lock);
    priv->usbdev = usbdev;

    int ret = 0;

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

    ret = mt7921_run_firmware(priv);
    if (ret) {
        printk("Failed to run firmware\n");
        goto err;
    }

    printk("MT7921 initialized successfully\n");

    usbdev->desc = priv;

    return 0;

err:
    free(priv);
    return ret;
}

int mt7921_remove(struct usbdevice_s *usbdev) { return 0; }

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
