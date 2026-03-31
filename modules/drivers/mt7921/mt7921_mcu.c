#include "mt7921.h"

static uint32_t mt7921_be32_to_cpu(uint32_t v) {
    return ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) |
           ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);
}

static uint32_t mt7921_le32_to_cpu(uint32_t v) { return v; }
static uint16_t mt7921_le16_to_cpu(uint16_t v) { return v; }

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

uint32_t mt7921_ram_get_data_mode(uint8_t feature_set) {
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

static int mt7921_mcu_parse_response(uint32_t cmd, const uint8_t *pkt,
                                     size_t pkt_len, void *resp,
                                     size_t resp_len) {
    const struct mt7921_mcu_rxd *rxd;
    size_t header_len = sizeof(struct mt7921_mcu_rxd);

    if (!pkt || pkt_len < header_len) {
        return -EINVAL;
    }

    rxd = (const struct mt7921_mcu_rxd *)pkt;
    (void)rxd;

    if (cmd == MT7921_MCU_CMD_PATCH_SEM_CONTROL ||
        cmd == MT7921_MCU_CMD_PATCH_FINISH_REQ) {
        uint8_t status = pkt_len > header_len ? pkt[header_len] : 0;

        if (resp && resp_len) {
            memset(resp, 0, resp_len);
            ((uint8_t *)resp)[0] = status;
            return 0;
        }

        return (int)status;
    }

    if (resp && resp_len) {
        size_t payload_off = header_len + 4;
        size_t copy_len = 0;

        if (pkt_len > payload_off) {
            copy_len = pkt_len - payload_off;
            if (copy_len > resp_len) {
                copy_len = resp_len;
            }
        }

        memset(resp, 0, resp_len);
        if (copy_len) {
            memcpy(resp, pkt + payload_off, copy_len);
        }
    }

    return 0;
}

int mt7921_mcu_send_msg(mt7921_priv_t *priv, uint32_t cmd, const void *req,
                        size_t req_len, bool wait_resp, void *resp,
                        size_t resp_len) {
    struct mt7921_mcu_txd txd;
    uint8_t *tx_buf = NULL;
    size_t tx_len = 0;
    enum mt7921_usb_out_ep out_ep;
    uint8_t seq = 0;
    uint8_t *resp_pkt = NULL;
    size_t resp_pkt_len = 0;
    int ret;

    mutex_lock(&priv->mcu_mutex);

    if (cmd == MT7921_MCU_CMD_FW_SCATTER) {
        out_ep = MT7921_USB_OUT_AC_BE;
        ret = mt7921_usb_send_raw(priv, out_ep, req, req_len);
        mutex_unlock(&priv->mcu_mutex);
        return ret;
    } else {
        uint8_t cmd_id = (uint8_t)(cmd & MT7921_MCU_CMD_FIELD_ID_MASK);
        uint8_t ext_id =
            (uint8_t)((cmd & MT7921_MCU_CMD_FIELD_EXT_ID_MASK) >> 8);

        tx_len = sizeof(txd) + req_len;
        tx_buf = malloc(tx_len);
        if (!tx_buf) {
            mutex_unlock(&priv->mcu_mutex);
            return -ENOMEM;
        }

        memset(&txd, 0, sizeof(txd));
        seq = (++priv->mcu_seq) & 0x0fU;
        if (!seq) {
            seq = (++priv->mcu_seq) & 0x0fU;
        }

        txd.txd[0] = (uint32_t)(tx_len & 0xffffU) | (2U << 23) | (0x20U << 25);
        txd.txd[1] = (1U << 31) | (1U << 16);
        txd.len = (uint16_t)(tx_len - sizeof(txd.txd));
        txd.pq_id = 0x8000;
        txd.cid = cmd_id;
        txd.pkt_type = 0xa0;
        txd.seq = seq;
        txd.ext_cid = ext_id;
        txd.s2d_index = 0;

        if (ext_id || (cmd & MT7921_MCU_CMD_FIELD_CE)) {
            txd.set_query = (cmd & MT7921_MCU_CMD_FIELD_QUERY) ? 0 : 1;
            txd.ext_cid_ack = ext_id ? 1 : 0;
        } else {
            txd.set_query = 3;
        }

        memcpy(tx_buf, &txd, sizeof(txd));
        if (req_len) {
            memcpy(tx_buf + sizeof(txd), req, req_len);
        }

        out_ep = MT7921_USB_OUT_INBAND_CMD;
        ret = mt7921_usb_send_raw(priv, out_ep, tx_buf, tx_len);
        free(tx_buf);
        if (ret || !wait_resp) {
            mutex_unlock(&priv->mcu_mutex);
            return ret;
        }
    }

    ret = mt7921_usb_wait_resp(priv, seq, MT7921_MCU_TIMEOUT_MS, &resp_pkt,
                               &resp_pkt_len);
    if (!ret) {
        ret = mt7921_mcu_parse_response(cmd, resp_pkt, resp_pkt_len, resp,
                                        resp_len);
    }

    free(resp_pkt);
    mutex_unlock(&priv->mcu_mutex);
    return ret;
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

int mt7921_mcu_init_download(mt7921_priv_t *priv, uint32_t addr, uint32_t len,
                             uint32_t mode) {
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

int mt7921_mcu_send_scatter(mt7921_priv_t *priv, uint8_t *data, size_t len) {
    size_t offset = 0;
    int ret;

    while (offset < len) {
        size_t chunk = MIN((size_t)MT7921_MCU_SCATTER_CHUNK, len - offset);

        ret = mt7921_mcu_send_msg(priv, MT7921_MCU_CMD_FW_SCATTER,
                                  data + offset, chunk, false, NULL, 0);
        if (ret) {
            return ret;
        }
        offset += chunk;
    }

    return 0;
}

int mt7921_mcu_start_patch(mt7921_priv_t *priv) {
    struct mt7921_mcu_patch_finish_req req;

    memset(&req, 0, sizeof(req));
    return mt7921_mcu_send_msg(priv, MT7921_MCU_CMD_PATCH_FINISH_REQ, &req,
                               sizeof(req), true, NULL, 0);
}

int mt7921_mcu_start_firmware(mt7921_priv_t *priv, uint32_t addr,
                              uint32_t option) {
    struct mt7921_mcu_fw_start_req req;

    req.option = option;
    req.addr = addr;
    return mt7921_mcu_send_msg(priv, MT7921_MCU_CMD_FW_START_REQ, &req,
                               sizeof(req), true, NULL, 0);
}

int mt7921_mcu_fw_log_2_host(mt7921_priv_t *priv, uint8_t ctrl) {
    struct mt7921_mcu_ce_fwlog_req req;

    req.ctrl_val = ctrl;
    memset(req.pad, 0, sizeof(req.pad));
    return mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_FWLOG_2_HOST, &req,
                               sizeof(req), false, NULL, 0);
}

void mt7921_parse_phy_cap(mt7921_priv_t *priv, const uint8_t *data,
                          size_t len) {
    const struct mt7921_phy_cap *cap;

    if (len < sizeof(struct mt7921_phy_cap)) {
        return;
    }

    cap = (const struct mt7921_phy_cap *)data;
    if (cap->nss >= 1 && cap->nss <= 8) {
        priv->antenna_mask = (uint8_t)((1U << cap->nss) - 1U);
    }

    priv->has_2ghz = (cap->hw_path & MT7921_HW_PATH_2G_BIT) != 0;
    priv->has_5ghz = (cap->hw_path & MT7921_HW_PATH_5G_BIT) != 0;
}

int mt7921_mcu_get_nic_capability(mt7921_priv_t *priv) {
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

    hdr = (const struct mt7921_cap_hdr *)buf;
    n_element = mt7921_le16_to_cpu(hdr->n_element_le);
    pos = sizeof(*hdr);

    for (i = 0; i < n_element; i++) {
        const struct mt7921_cap_tlv *tlv;
        uint32_t type;
        uint32_t len;

        if (pos + sizeof(struct mt7921_cap_tlv) > sizeof(buf)) {
            break;
        }

        tlv = (const struct mt7921_cap_tlv *)(buf + pos);
        type = mt7921_le32_to_cpu(tlv->type_le);
        len = mt7921_le32_to_cpu(tlv->len_le);
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

    return 0;
}

int mt7921_send_patch_firmware(mt7921_priv_t *priv, uint8_t *data,
                               size_t size) {
    const struct mt7921_patch_hdr *hdr = (const struct mt7921_patch_hdr *)data;
    int sem;
    int ret = 0;
    uint32_t i;
    uint32_t n_region;

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

    n_region = mt7921_be32_to_cpu(hdr->desc.n_region_be);
    if (size < sizeof(*hdr) + n_region * sizeof(struct mt7921_patch_sec)) {
        ret = -EINVAL;
        goto out;
    }

    for (i = 0; i < n_region; i++) {
        const struct mt7921_patch_sec *sec =
            (const struct mt7921_patch_sec *)(data + sizeof(*hdr) +
                                              i * sizeof(*sec));
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

out:
    sem = mt7921_mcu_patch_sem_ctrl(priv, false);
    if (sem != MT7921_PATCH_REL_SEM_SUCCESS) {
        return -EAGAIN;
    }

    return ret;
}

int mt7921_send_ram_firmware(mt7921_priv_t *priv, uint8_t *data, size_t size) {
    const struct mt7921_fw_trailer *trailer;
    const struct mt7921_fw_region *region;
    size_t region_table_size;
    size_t payload_off = 0;
    uint32_t override = 0;
    uint32_t option = 0;
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
