#include "mt7921.h"

#include <net/rtnl.h>
#include <net/wifi_rtnl.h>

#define MT7921_WIFI_MTU 1500U
#define MT7921_ETH_HLEN 14U
#define MT7921_IEEE80211_HDRLEN 24U
#define MT7921_BEACON_FIXED_LEN 12U
#define MT7921_WLAN_EID_SSID 0U
#define MT7921_WLAN_EID_DS_PARAMS 3U
#define MT7921_WLAN_EID_RSN 48U
#define MT7921_WLAN_EID_VENDOR_SPECIFIC 221U
#define MT7921_CAPAB_PRIVACY (1U << 4)
#define MT7921_IEEE80211_FTYPE_MGMT 0U
#define MT7921_IEEE80211_STYPE_PROBE_RESP 5U
#define MT7921_IEEE80211_STYPE_BEACON 8U
#define MT7921_PRXV_RCPI0_MASK 0x000000ffU
#define MT7921_PRXV_RCPI1_MASK 0x0000ff00U
#define MT7921_PRXV_RCPI2_MASK 0x00ff0000U
#define MT7921_PRXV_RCPI3_MASK 0xff000000U

#define MT7921_TX_PKT_FMT_SF 1U
#define MT7921_TX_HDR_FORMAT_802_3 0U
#define MT7921_TX_LMAC_AC00 0U
#define MT7921_TX_LMAC_AC01 1U
#define MT7921_TX_LMAC_AC02 2U
#define MT7921_TX_LMAC_AC03 3U

#define MT7921_TXD0_Q_IDX_MASK (0x7fU << 25)
#define MT7921_TXD0_PKT_FMT_MASK (0x3U << 23)
#define MT7921_TXD0_TX_BYTES_MASK 0x0000ffffU
#define MT7921_TXD1_LONG_FORMAT (1U << 31)
#define MT7921_TXD1_OWN_MAC_MASK (0x3fU << 24)
#define MT7921_TXD1_TID_MASK (0x7U << 20)
#define MT7921_TXD1_HDR_FORMAT_MASK (0x3U << 16)
#define MT7921_TXD1_ETH_802_3 (1U << 15)
#define MT7921_TXD1_WLAN_IDX_MASK 0x000003ffU
#define MT7921_TXD2_MULTICAST (1U << 10)
#define MT7921_TXD2_FRAME_TYPE_MASK (0x3U << 4)
#define MT7921_TXD2_SUB_TYPE_MASK 0x0000000fU
#define MT7921_TXD3_REM_TX_COUNT_MASK (0x1fU << 11)

static uint32_t mt7921_field_prep(uint32_t mask, uint32_t val) {
    uint32_t shift = (uint32_t)__builtin_ctz(mask);
    return (val << shift) & mask;
}

static uint8_t mt7921_tid_to_lmac_qidx(uint8_t tid) {
    switch (tid & 0x7) {
    case 1:
    case 2:
        return MT7921_TX_LMAC_AC01;
    case 4:
    case 5:
        return MT7921_TX_LMAC_AC02;
    case 6:
    case 7:
        return MT7921_TX_LMAC_AC03;
    default:
        return MT7921_TX_LMAC_AC00;
    }
}

static uint8_t mt7921_band_from_bss(const wifi_bss_info_t *bss) {
    if (!bss) {
        return 0;
    }
    if (bss->freq_mhz >= 5925) {
        return 2;
    }
    if (bss->freq_mhz >= 4900) {
        return 1;
    }
    return 0;
}

static uint8_t mt7921_scan_band_from_bss(const wifi_bss_info_t *bss) {
    if (!bss) {
        return 1;
    }
    if (bss->freq_mhz >= 5925) {
        return 3;
    }
    if (bss->freq_mhz >= 4900) {
        return 2;
    }
    return 1;
}

static uint8_t mt7921_phymode_from_bss(mt7921_priv_t *priv,
                                       const wifi_bss_info_t *bss) {
    uint8_t mode = 0;

    if (!priv || !bss) {
        return 0;
    }
    if (bss->freq_mhz >= 4900) {
        mode |= MT7921_PHY_MODE_A;
        if (priv->has_5ghz) {
            mode |=
                MT7921_PHY_MODE_AN | MT7921_PHY_MODE_AC | MT7921_PHY_MODE_AX_5G;
        }
    } else {
        mode |= MT7921_PHY_MODE_B | MT7921_PHY_MODE_G;
        if (priv->has_2ghz) {
            mode |= MT7921_PHY_MODE_GN | MT7921_PHY_MODE_AX_24G;
        }
    }

    return mode;
}

static int mt7921_mcu_dev_info_update(mt7921_priv_t *priv, bool enable) {
    struct mt7921_dev_info_req req;
    wifi_status_t status;

    if (!priv || !priv->wifi) {
        return -EINVAL;
    }

    memset(&req, 0, sizeof(req));
    wifi_get_status(priv->wifi, &status);
    req.hdr.omac_idx = status.tx_ctx.own_mac_idx;
    req.hdr.band_idx =
        priv->have_target_bss ? mt7921_band_from_bss(&priv->target_bss) : 0;
    req.tlv.tag = MT7921_DEV_INFO_ACTIVE;
    req.tlv.len = sizeof(req.tlv);
    req.tlv.active = enable ? 1 : 0;
    req.tlv.link_idx = 0;
    memcpy(req.tlv.omac_addr, priv->macaddr, sizeof(req.tlv.omac_addr));

    return mt7921_mcu_send_msg(priv, MT7921_MCU_UNI_CMD_DEV_INFO_UPDATE, &req,
                               sizeof(req), true, NULL, 0);
}

static int mt7921_mcu_bss_basic_update(mt7921_priv_t *priv, bool enable) {
    struct mt7921_bss_basic_req req;
    wifi_status_t status;
    uint16_t wlan_idx = 0;

    if (!priv || !priv->wifi || !priv->have_target_bss) {
        return -EINVAL;
    }

    memset(&req, 0, sizeof(req));
    wifi_get_status(priv->wifi, &status);
    wlan_idx = status.tx_ctx.wlan_idx;

    req.basic.tag = MT7921_UNI_BSS_INFO_BASIC;
    req.basic.len = sizeof(req.basic);
    req.basic.active = enable ? 1 : 0;
    req.basic.omac_idx = status.tx_ctx.own_mac_idx;
    req.basic.hw_bss_idx = 0;
    req.basic.band_idx = mt7921_band_from_bss(&priv->target_bss);
    req.basic.conn_type = MT7921_CONNECTION_INFRA_STA;
    req.basic.conn_state =
        enable ? MT7921_CONN_STATE_CONNECT : MT7921_CONN_STATE_DISCONNECT;
    req.basic.wmm_idx = 0;
    memcpy(req.basic.bssid, priv->target_bss.bssid, sizeof(req.basic.bssid));
    req.basic.bmc_tx_wlan_idx = wlan_idx;
    req.basic.bcn_interval = 100;
    req.basic.dtim_period = 1;
    req.basic.phymode = mt7921_phymode_from_bss(priv, &priv->target_bss);
    req.basic.sta_idx = wlan_idx;
    req.basic.nonht_basic_phy = req.basic.phymode;
    req.basic.phymode_ext = 0;
    req.basic.link_idx = 0;
    req.qos.tag = MT7921_UNI_BSS_INFO_QBSS;
    req.qos.len = sizeof(req.qos);
    req.qos.qos = 1;

    return mt7921_mcu_send_msg(priv, MT7921_MCU_UNI_CMD_BSS_INFO_UPDATE, &req,
                               sizeof(req), true, NULL, 0);
}

static int mt7921_mcu_bss_rlm_update(mt7921_priv_t *priv) {
    struct mt7921_bss_rlm_req req;

    if (!priv || !priv->have_target_bss) {
        return -EINVAL;
    }

    memset(&req, 0, sizeof(req));
    req.rlm.tag = MT7921_UNI_BSS_INFO_RLM;
    req.rlm.len = sizeof(req.rlm);
    req.rlm.control_channel = priv->target_bss.channel;
    req.rlm.center_chan = priv->target_bss.channel;
    req.rlm.center_chan2 = 0;
    req.rlm.bw = 0;
    req.rlm.tx_streams =
        MAX((uint8_t)1, (uint8_t)__builtin_popcount(priv->antenna_mask));
    req.rlm.rx_streams = req.rlm.tx_streams;
    req.rlm.short_st = 1;
    req.rlm.ht_op_info = 0;
    req.rlm.sco = 0;
    req.rlm.band = mt7921_band_from_bss(&priv->target_bss);

    return mt7921_mcu_send_msg(priv, MT7921_MCU_UNI_CMD_BSS_INFO_UPDATE, &req,
                               sizeof(req), true, NULL, 0);
}

static int mt7921_mcu_tx_params_update(mt7921_priv_t *priv) {
    struct mt7921_mcu_tx_req req;
    static const int to_aci[] = {1, 0, 2, 3};

    if (!priv) {
        return -EINVAL;
    }

    memset(&req, 0, sizeof(req));
    req.bss_idx = 0;
    req.qos = 1;
    req.wmm_idx = 0;

    for (int ac = 0; ac < 4; ac++) {
        struct mt7921_mcu_tx_edca *e = &req.edca[to_aci[ac]];
        e->aifs = 2;
        e->txop = 0;
        e->cw_min = 5;
        e->cw_max = 10;
    }

    return mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_SET_EDCA_PARMS, &req,
                               sizeof(req), false, NULL, 0);
}

static int mt7921_mcu_bss_pm_set(mt7921_priv_t *priv, bool enable) {
    struct {
        uint8_t bss_idx;
        uint8_t dtim_period;
        uint16_t aid;
        uint16_t bcn_interval;
        uint16_t atim_window;
        uint8_t uapsd;
        uint8_t bmc_delivered_ac;
        uint8_t bmc_triggered_ac;
        uint8_t pad;
    } __attribute__((packed)) req;
    struct {
        uint8_t bss_idx;
        uint8_t pad[3];
    } __attribute__((packed)) req_hdr;
    int ret;

    memset(&req, 0, sizeof(req));
    memset(&req_hdr, 0, sizeof(req_hdr));
    req.bss_idx = 0;
    req.dtim_period = 1;
    req.aid = 1;
    req.bcn_interval = 100;
    req_hdr.bss_idx = 0;

    ret = mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_SET_BSS_ABORT, &req_hdr,
                              sizeof(req_hdr), false, NULL, 0);
    if (ret < 0 || !enable) {
        return ret;
    }

    return mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_SET_BSS_CONNECTED, &req,
                               sizeof(req), false, NULL, 0);
}

#define MT_RXD1_NORMAL_GROUP_1 (1U << 11)
#define MT_RXD1_NORMAL_GROUP_2 (1U << 12)
#define MT_RXD1_NORMAL_GROUP_3 (1U << 13)
#define MT_RXD1_NORMAL_GROUP_4 (1U << 14)
#define MT_RXD1_NORMAL_GROUP_5 (1U << 15)
#define MT_RXD1_NORMAL_CM (1U << 23)
#define MT_RXD1_NORMAL_ICV_ERR (1U << 25)
#define MT_RXD1_NORMAL_TKIP_MIC_ERR (1U << 26)
#define MT_RXD1_NORMAL_FCS_ERR (1U << 27)

#define MT_RXD2_NORMAL_HDR_TRANS (1U << 13)
#define MT_RXD2_NORMAL_HDR_OFFSET_MASK (0x3U << 14)
#define MT_RXD2_NORMAL_AMSDU_ERR (1U << 23)
#define MT_RXD2_NORMAL_MAX_LEN_ERROR (1U << 24)
#define MT_RXD2_NORMAL_HDR_TRANS_ERROR (1U << 25)
#define MT_RXD2_NORMAL_NDATA (1U << 29)

static int mt7921_rx_decap_8023(const uint8_t *raw, size_t raw_len, void *out,
                                uint32_t out_len) {
    uint32_t rxd0 = 0;
    uint32_t rxd1 = 0;
    uint32_t rxd2 = 0;
    uint8_t remove_pad = 0;
    size_t hdr_gap = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (!raw || !out) {
        return -EINVAL;
    }
    if (raw_len < 24) {
        return -EINVAL;
    }

    memcpy(&rxd0, raw, sizeof(rxd0));
    memcpy(&rxd1, raw + 4, sizeof(rxd1));
    memcpy(&rxd2, raw + 8, sizeof(rxd2));

    {
        uint32_t pkt_type =
            (rxd0 & MT_RXD0_PKT_TYPE_MASK) >> MT_RXD0_PKT_TYPE_SHIFT;
        if (pkt_type != MT7921_PKT_TYPE_NORMAL &&
            pkt_type != MT7921_PKT_TYPE_NORMAL_MCU) {
            return -EOPNOTSUPP;
        }
    }
    if (rxd1 & (MT_RXD1_NORMAL_ICV_ERR | MT_RXD1_NORMAL_TKIP_MIC_ERR |
                MT_RXD1_NORMAL_FCS_ERR)) {
        return -EINVAL;
    }
    if (rxd2 & (MT_RXD2_NORMAL_AMSDU_ERR | MT_RXD2_NORMAL_MAX_LEN_ERROR |
                MT_RXD2_NORMAL_HDR_TRANS_ERROR | MT_RXD2_NORMAL_NDATA)) {
        return -EINVAL;
    }
    if (!(rxd2 & MT_RXD2_NORMAL_HDR_TRANS) || (rxd1 & MT_RXD1_NORMAL_CM)) {
        return -EOPNOTSUPP;
    }

    hdr_gap = 6U * sizeof(uint32_t);
    if (rxd1 & MT_RXD1_NORMAL_GROUP_4) {
        hdr_gap += 4U * sizeof(uint32_t);
    }
    if (rxd1 & MT_RXD1_NORMAL_GROUP_1) {
        hdr_gap += 4U * sizeof(uint32_t);
    }
    if (rxd1 & MT_RXD1_NORMAL_GROUP_2) {
        hdr_gap += 2U * sizeof(uint32_t);
    }
    if (rxd1 & MT_RXD1_NORMAL_GROUP_3) {
        hdr_gap += 2U * sizeof(uint32_t);
        if (rxd1 & MT_RXD1_NORMAL_GROUP_5) {
            hdr_gap += 18U * sizeof(uint32_t);
        }
    }

    remove_pad = (uint8_t)((rxd2 & MT_RXD2_NORMAL_HDR_OFFSET_MASK) >> 14);
    hdr_gap += (size_t)remove_pad * 2U;

    if (hdr_gap >= raw_len) {
        return -EINVAL;
    }

    payload = raw + hdr_gap;
    payload_len = raw_len - hdr_gap;
    if (payload_len < MT7921_ETH_HLEN) {
        return -EINVAL;
    }
    if (payload_len > out_len) {
        return -EMSGSIZE;
    }

    memcpy(out, payload, payload_len);
    return (int)payload_len;
}

static int16_t mt7921_rcpi_to_dbm(uint32_t val, uint32_t mask, uint8_t shift) {
    int rcpi = (int)((val & mask) >> shift);
    return (int16_t)((rcpi - 220) / 2);
}

static uint16_t mt7921_channel_to_freq(uint8_t channel) {
    if (channel == 14) {
        return 2484;
    }
    if (channel >= 1 && channel <= 13) {
        return (uint16_t)(2407 + 5 * channel);
    }
    if (channel >= 1 && channel <= 233 && channel > 180) {
        return (uint16_t)(5950 + 5 * channel);
    }
    if (channel > 0) {
        return (uint16_t)(5000 + 5 * channel);
    }
    return 0;
}

static void mt7921_scan_cache_clear(mt7921_priv_t *priv) {
    if (!priv) {
        return;
    }

    spin_lock(&priv->scan_lock);
    memset(priv->scan_results, 0, sizeof(priv->scan_results));
    priv->scan_result_count = 0;
    spin_unlock(&priv->scan_lock);
}

static void mt7921_scan_cache_commit(mt7921_priv_t *priv) {
    wifi_bss_info_t snapshot[WIFI_MAX_SCAN_RESULTS];
    uint32_t count = 0;

    if (!priv || !priv->wifi) {
        return;
    }

    spin_lock(&priv->scan_lock);
    count = MIN(priv->scan_result_count, (uint32_t)WIFI_MAX_SCAN_RESULTS);
    memcpy(snapshot, priv->scan_results, count * sizeof(snapshot[0]));
    spin_unlock(&priv->scan_lock);

    wifi_report_scan_results(priv->wifi, snapshot, count);
}

static void mt7921_scan_cache_upsert(mt7921_priv_t *priv,
                                     const wifi_bss_info_t *bss) {
    uint32_t slot = WIFI_MAX_SCAN_RESULTS;

    if (!priv || !bss) {
        return;
    }

    spin_lock(&priv->scan_lock);
    for (uint32_t i = 0; i < priv->scan_result_count; i++) {
        if (memcmp(priv->scan_results[i].bssid, bss->bssid, 6) == 0) {
            slot = i;
            break;
        }
    }

    if (slot == WIFI_MAX_SCAN_RESULTS) {
        if (priv->scan_result_count < WIFI_MAX_SCAN_RESULTS) {
            slot = priv->scan_result_count++;
        } else {
            int16_t weakest = priv->scan_results[0].signal_dbm;
            slot = 0;
            for (uint32_t i = 1; i < WIFI_MAX_SCAN_RESULTS; i++) {
                if (priv->scan_results[i].signal_dbm < weakest) {
                    weakest = priv->scan_results[i].signal_dbm;
                    slot = i;
                }
            }
            if (bss->signal_dbm <= weakest) {
                spin_unlock(&priv->scan_lock);
                return;
            }
        }
    }

    priv->scan_results[slot] = *bss;
    spin_unlock(&priv->scan_lock);
}

static int mt7921_scan_cache_find(mt7921_priv_t *priv,
                                  const wifi_connect_params_t *params,
                                  wifi_bss_info_t *out_bss) {
    int best = -1;

    if (!priv || !params || !out_bss) {
        return -EINVAL;
    }

    spin_lock(&priv->scan_lock);
    for (uint32_t i = 0; i < priv->scan_result_count; i++) {
        wifi_bss_info_t *bss = &priv->scan_results[i];

        if (params->have_bssid &&
            memcmp(bss->bssid, params->bssid, sizeof(bss->bssid)) != 0) {
            continue;
        }
        if (params->ssid_len != bss->ssid_len ||
            memcmp(bss->ssid, params->ssid, params->ssid_len) != 0) {
            continue;
        }

        if (best < 0 || bss->signal_dbm > priv->scan_results[best].signal_dbm) {
            best = (int)i;
        }
    }

    if (best >= 0) {
        *out_bss = priv->scan_results[best];
    }
    spin_unlock(&priv->scan_lock);

    return best >= 0 ? 0 : -ENOENT;
}

static bool mt7921_parse_scan_mgmt_frame(mt7921_priv_t *priv,
                                         const uint8_t *raw, size_t raw_len) {
    uint32_t rxd0 = 0;
    uint32_t rxd1 = 0;
    uint32_t rxd2 = 0;
    uint32_t rxd3 = 0;
    size_t hdr_gap = 0;
    const uint8_t *frame = NULL;
    size_t frame_len = 0;
    uint16_t fc = 0;
    uint8_t type = 0;
    uint8_t subtype = 0;
    const uint8_t *ies = NULL;
    size_t ies_len = 0;
    wifi_bss_info_t bss;

    if (!priv || !raw || raw_len < 24) {
        return false;
    }

    memcpy(&rxd0, raw, sizeof(rxd0));
    memcpy(&rxd1, raw + 4, sizeof(rxd1));
    memcpy(&rxd2, raw + 8, sizeof(rxd2));
    memcpy(&rxd3, raw + 12, sizeof(rxd3));

    if (((rxd0 & MT_RXD0_PKT_TYPE_MASK) >> MT_RXD0_PKT_TYPE_SHIFT) !=
        MT7921_PKT_TYPE_NORMAL) {
        return false;
    }
    if (rxd1 & (MT_RXD1_NORMAL_ICV_ERR | MT_RXD1_NORMAL_TKIP_MIC_ERR |
                MT_RXD1_NORMAL_FCS_ERR)) {
        return false;
    }
    if (rxd2 & (MT_RXD2_NORMAL_AMSDU_ERR | MT_RXD2_NORMAL_MAX_LEN_ERROR |
                MT_RXD2_NORMAL_NDATA)) {
        return false;
    }

    hdr_gap = 6U * sizeof(uint32_t);
    if (rxd1 & MT_RXD1_NORMAL_GROUP_4) {
        hdr_gap += 4U * sizeof(uint32_t);
    }
    if (rxd1 & MT_RXD1_NORMAL_GROUP_1) {
        hdr_gap += 4U * sizeof(uint32_t);
    }
    if (rxd1 & MT_RXD1_NORMAL_GROUP_2) {
        hdr_gap += 2U * sizeof(uint32_t);
    }
    if (rxd1 & MT_RXD1_NORMAL_GROUP_3) {
        hdr_gap += 2U * sizeof(uint32_t);
        if (rxd1 & MT_RXD1_NORMAL_GROUP_5) {
            hdr_gap += 18U * sizeof(uint32_t);
        }
    }
    hdr_gap += (size_t)(((rxd2 & MT_RXD2_NORMAL_HDR_OFFSET_MASK) >> 14) * 2U);

    if (hdr_gap + MT7921_IEEE80211_HDRLEN + MT7921_BEACON_FIXED_LEN > raw_len) {
        return false;
    }

    frame = raw + hdr_gap;
    frame_len = raw_len - hdr_gap;
    memcpy(&fc, frame, sizeof(fc));
    type = (uint8_t)((fc >> 2) & 0x3);
    subtype = (uint8_t)((fc >> 4) & 0xf);
    if (type != MT7921_IEEE80211_FTYPE_MGMT ||
        (subtype != MT7921_IEEE80211_STYPE_BEACON &&
         subtype != MT7921_IEEE80211_STYPE_PROBE_RESP)) {
        return false;
    }

    memset(&bss, 0, sizeof(bss));
    memcpy(bss.bssid, frame + 16, 6);
    bss.channel = (uint8_t)((rxd3 >> 8) & 0xffU);
    bss.freq_mhz = mt7921_channel_to_freq(bss.channel);

    if (rxd1 & MT_RXD1_NORMAL_GROUP_3) {
        size_t rxv_off = 6U * sizeof(uint32_t);
        uint32_t rxv1 = 0;
        int16_t sig = -127;
        if (rxd1 & MT_RXD1_NORMAL_GROUP_4) {
            rxv_off += 4U * sizeof(uint32_t);
        }
        if (rxd1 & MT_RXD1_NORMAL_GROUP_1) {
            rxv_off += 4U * sizeof(uint32_t);
        }
        if (rxd1 & MT_RXD1_NORMAL_GROUP_2) {
            rxv_off += 2U * sizeof(uint32_t);
        }
        if (rxv_off + 8U <= raw_len) {
            memcpy(&rxv1, raw + rxv_off + 4U, sizeof(rxv1));
            sig = mt7921_rcpi_to_dbm(rxv1, MT7921_PRXV_RCPI0_MASK, 0);
            sig = MAX(sig, mt7921_rcpi_to_dbm(rxv1, MT7921_PRXV_RCPI1_MASK, 8));
            sig =
                MAX(sig, mt7921_rcpi_to_dbm(rxv1, MT7921_PRXV_RCPI2_MASK, 16));
            sig =
                MAX(sig, mt7921_rcpi_to_dbm(rxv1, MT7921_PRXV_RCPI3_MASK, 24));
        }
        bss.signal_dbm = sig;
    }

    {
        uint16_t capab = 0;
        memcpy(&capab, frame + MT7921_IEEE80211_HDRLEN + 10, sizeof(capab));
        if (capab & MT7921_CAPAB_PRIVACY) {
            bss.flags |= WIFI_BSS_FLAG_PRIVACY;
        }
    }

    ies = frame + MT7921_IEEE80211_HDRLEN + MT7921_BEACON_FIXED_LEN;
    ies_len = frame_len - (MT7921_IEEE80211_HDRLEN + MT7921_BEACON_FIXED_LEN);
    while (ies_len >= 2) {
        uint8_t eid = ies[0];
        uint8_t elen = ies[1];

        if ((size_t)elen + 2U > ies_len) {
            break;
        }

        if (eid == MT7921_WLAN_EID_SSID) {
            bss.ssid_len = MIN((uint32_t)elen, (uint32_t)WIFI_MAX_SSID_LEN);
            memcpy(bss.ssid, ies + 2, bss.ssid_len);
        } else if (eid == MT7921_WLAN_EID_DS_PARAMS && elen >= 1) {
            bss.channel = ies[2];
            bss.freq_mhz = mt7921_channel_to_freq(bss.channel);
        } else if (eid == MT7921_WLAN_EID_RSN) {
            bss.flags |= WIFI_BSS_FLAG_WPA2;
        } else if (eid == MT7921_WLAN_EID_VENDOR_SPECIFIC && elen >= 4 &&
                   ies[2] == 0x00 && ies[3] == 0x50 && ies[4] == 0xf2 &&
                   ies[5] == 0x01) {
            bss.flags |= WIFI_BSS_FLAG_WPA;
        }

        ies += (size_t)elen + 2U;
        ies_len -= (size_t)elen + 2U;
    }

    mt7921_scan_cache_upsert(priv, &bss);
    return true;
}

static int mt7921_mcu_hw_scan(mt7921_priv_t *priv) {
    struct mt7921_mcu_hw_scan_req req;

    if (!priv) {
        return -EINVAL;
    }

    memset(&req, 0, sizeof(req));
    mt7921_scan_cache_clear(priv);

    priv->scan_seq = (uint8_t)((priv->scan_seq + 1U) & 0x7fU);
    if (!priv->scan_seq) {
        priv->scan_seq = 1U;
    }

    req.seq_num = priv->scan_seq;
    req.bss_idx = 0;
    req.scan_type = 0;
    req.ssid_type = 1U << 0;
    req.ssids_num = 0;
    req.probe_req_num = 0;
    req.scan_func = MT7921_SCAN_FUNC_SPLIT_SCAN;
    req.version = 1;
    req.channel_type = 0;
    req.channels_num = 0;
    req.ext_channels_num = 0;

    return mt7921_mcu_send_msg(priv, MT7921_MCU_CE_CMD_START_HW_SCAN, &req,
                               sizeof(req), false, NULL, 0);
}

static int mt7921_netdev_send(void *dev_desc, void *data, uint32_t len) {
    mt7921_priv_t *priv = (mt7921_priv_t *)dev_desc;
    wifi_status_t status;
    uint8_t *buf = NULL;
    uint32_t *txwi = NULL;
    uint16_t ethertype = 0;
    uint8_t tid = 0;
    uint8_t q_idx = 0;
    uint8_t own_mac_idx = 0;
    uint16_t wlan_idx = 0;
    int ret = 0;

    if (!priv || !data || !len) {
        return -EINVAL;
    }
    if (priv->removed) {
        return -ENODEV;
    }
    if (!priv->wifi) {
        return -ENODEV;
    }

    if (wifi_get_status(priv->wifi, &status) < 0) {
        return -ENODEV;
    }

    own_mac_idx = status.tx_ctx.own_mac_idx;
    wlan_idx = status.tx_ctx.wlan_idx;
    tid = 0;
    q_idx = mt7921_tid_to_lmac_qidx(tid);

    buf = malloc(MT7921_SDIO_TXD_SIZE + len);
    if (!buf) {
        return -ENOMEM;
    }

    memset(buf, 0, MT7921_SDIO_TXD_SIZE + len);
    txwi = (uint32_t *)buf;
    txwi[0] =
        mt7921_field_prep(MT7921_TXD0_TX_BYTES_MASK,
                          MT7921_SDIO_TXD_SIZE + len) |
        mt7921_field_prep(MT7921_TXD0_PKT_FMT_MASK, MT7921_TX_PKT_FMT_SF) |
        mt7921_field_prep(MT7921_TXD0_Q_IDX_MASK, q_idx);
    txwi[1] = MT7921_TXD1_LONG_FORMAT |
              mt7921_field_prep(MT7921_TXD1_WLAN_IDX_MASK, wlan_idx) |
              mt7921_field_prep(MT7921_TXD1_OWN_MAC_MASK, own_mac_idx) |
              mt7921_field_prep(MT7921_TXD1_HDR_FORMAT_MASK,
                                MT7921_TX_HDR_FORMAT_802_3) |
              mt7921_field_prep(MT7921_TXD1_TID_MASK, tid);
    txwi[2] = mt7921_field_prep(MT7921_TXD2_FRAME_TYPE_MASK, 2) |
              mt7921_field_prep(MT7921_TXD2_SUB_TYPE_MASK, 0);
    txwi[3] = mt7921_field_prep(MT7921_TXD3_REM_TX_COUNT_MASK, 15);

    if (len >= MT7921_ETH_HLEN) {
        memcpy(&ethertype, (uint8_t *)data + 12, sizeof(ethertype));
        ethertype = __builtin_bswap16(ethertype);
        if (ethertype >= 0x0600) {
            txwi[1] |= MT7921_TXD1_ETH_802_3;
        }
        if (((uint8_t *)data)[0] & 0x01U) {
            txwi[2] |= MT7921_TXD2_MULTICAST;
        }
    }

    memcpy(buf + MT7921_SDIO_TXD_SIZE, data, len);
    ret = mt7921_usb_send_raw(priv, MT7921_USB_OUT_AC_BE, buf,
                              MT7921_SDIO_TXD_SIZE + len);
    free(buf);
    return ret;
}

static int mt7921_netdev_recv(void *dev_desc, void *data, uint32_t len) {
    mt7921_priv_t *priv = (mt7921_priv_t *)dev_desc;
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int ret;

    if (!priv || !data || !len) {
        return -EINVAL;
    }
    if (priv->removed) {
        return -ENODEV;
    }

    for (;;) {
        ret = mt7921_data_pop(priv, &raw, &raw_len);
        if (ret < 0) {
            return ret;
        }

        if (mt7921_parse_scan_mgmt_frame(priv, raw, raw_len)) {
            free(raw);
            continue;
        }

        ret = mt7921_rx_decap_8023(raw, raw_len, data, len);
        free(raw);

        if (ret >= 0) {
            return ret;
        }

        if ((ret == -EOPNOTSUPP || ret == -EINVAL) && !priv->warned_rx_drop) {
            printk("mt7921: dropping RX frames until full mt76 descriptor "
                   "decode is implemented\n");
            priv->warned_rx_drop = true;
        }

        if (ret == -EMSGSIZE) {
            return ret;
        }
    }
}

static int mt7921_wifi_start(wifi_device_t *wifi) {
    mt7921_priv_t *priv = wifi ? (mt7921_priv_t *)wifi->drv_priv : NULL;

    if (!priv) {
        return -EINVAL;
    }
    if (priv->removed) {
        return -ENODEV;
    }

    wifi_report_state(wifi, WIFI_STATE_IDLE, 0);
    return 0;
}

static int mt7921_wifi_stop(wifi_device_t *wifi) {
    mt7921_priv_t *priv = wifi ? (mt7921_priv_t *)wifi->drv_priv : NULL;

    if (!priv) {
        return -EINVAL;
    }

    wifi_report_state(wifi, WIFI_STATE_DOWN, 0);
    return 0;
}

static int mt7921_wifi_scan(wifi_device_t *wifi) {
    mt7921_priv_t *priv = wifi ? (mt7921_priv_t *)wifi->drv_priv : NULL;

    if (!priv) {
        return -EINVAL;
    }
    if (priv->removed) {
        return -ENODEV;
    }

    return mt7921_mcu_hw_scan(priv);
}

static int mt7921_wifi_connect(wifi_device_t *wifi,
                               const wifi_connect_params_t *params) {
    mt7921_priv_t *priv = wifi ? (mt7921_priv_t *)wifi->drv_priv : NULL;
    wifi_bss_info_t bss;
    int ret;

    if (!priv || !params) {
        return -EINVAL;
    }
    if (priv->removed) {
        return -ENODEV;
    }
    if (!params->ssid_len) {
        return -EINVAL;
    }

    ret = mt7921_scan_cache_find(priv, params, &bss);
    if (ret < 0) {
        printk("mt7921: no scan result matches SSID \"%s\"\n",
               (int)params->ssid_len, params->ssid);
        return ret;
    }

    if (bss.flags & (WIFI_BSS_FLAG_WPA | WIFI_BSS_FLAG_WPA2 |
                     WIFI_BSS_FLAG_WPA3 | WIFI_BSS_FLAG_PRIVACY)) {
        printk("mt7921: selected BSS %02x:%02x:%02x:%02x:%02x:%02x for "
               "\"%s\", but protected-network association is not "
               "implemented yet\n",
               bss.bssid[0], bss.bssid[1], bss.bssid[2], bss.bssid[3],
               bss.bssid[4], bss.bssid[5], (int)params->ssid_len, params->ssid);
        return -EOPNOTSUPP;
    }

    spin_lock(&priv->scan_lock);
    priv->target_bss = bss;
    priv->have_target_bss = true;
    spin_unlock(&priv->scan_lock);

    ret = mt7921_mcu_dev_info_update(priv, true);
    if (ret < 0) {
        return ret;
    }

    ret = mt7921_mcu_bss_basic_update(priv, true);
    if (ret < 0) {
        return ret;
    }

    ret = mt7921_mcu_bss_rlm_update(priv);
    if (ret < 0) {
        return ret;
    }

    ret = mt7921_mcu_tx_params_update(priv);
    if (ret < 0) {
        return ret;
    }

    ret = mt7921_mcu_bss_pm_set(priv, true);
    if (ret < 0) {
        return ret;
    }

    printk("mt7921: configured open BSS %02x:%02x:%02x:%02x:%02x:%02x "
           "channel=%u for \"%.*s\"\n",
           bss.bssid[0], bss.bssid[1], bss.bssid[2], bss.bssid[3], bss.bssid[4],
           bss.bssid[5], bss.channel, (int)params->ssid_len, params->ssid);
    wifi_report_connected(wifi, params, &bss);
    return 0;
}

static int mt7921_wifi_disconnect(wifi_device_t *wifi) {
    mt7921_priv_t *priv = wifi ? (mt7921_priv_t *)wifi->drv_priv : NULL;

    if (!priv) {
        return -EINVAL;
    }
    if (priv->removed) {
        return -ENODEV;
    }

    (void)mt7921_mcu_bss_pm_set(priv, false);
    (void)mt7921_mcu_bss_basic_update(priv, false);
    (void)mt7921_mcu_dev_info_update(priv, false);

    spin_lock(&priv->scan_lock);
    priv->have_target_bss = false;
    memset(&priv->target_bss, 0, sizeof(priv->target_bss));
    spin_unlock(&priv->scan_lock);

    wifi_report_disconnected(wifi, 0);
    return 0;
}

static int mt7921_wifi_set_tx_context(wifi_device_t *wifi,
                                      const wifi_tx_context_t *tx_ctx) {
    mt7921_priv_t *priv = wifi ? (mt7921_priv_t *)wifi->drv_priv : NULL;

    if (!priv || !tx_ctx) {
        return -EINVAL;
    }
    if (priv->removed) {
        return -ENODEV;
    }

    return 0;
}

static int mt7921_wifi_set_bssid(wifi_device_t *wifi, const uint8_t *bssid) {
    mt7921_priv_t *priv = wifi ? (mt7921_priv_t *)wifi->drv_priv : NULL;

    if (!priv || !bssid) {
        return -EINVAL;
    }
    if (priv->removed) {
        return -ENODEV;
    }

    return 0;
}

static const wifi_driver_ops_t mt7921_wifi_ops = {
    .start = mt7921_wifi_start,
    .stop = mt7921_wifi_stop,
    .scan = mt7921_wifi_scan,
    .connect = mt7921_wifi_connect,
    .disconnect = mt7921_wifi_disconnect,
    .set_tx_context = mt7921_wifi_set_tx_context,
    .set_bssid = mt7921_wifi_set_bssid,
};

int mt7921_wifi_register(mt7921_priv_t *priv) {
    int ret;

    if (!priv) {
        return -EINVAL;
    }
    if (priv->wifi && priv->rtnl_dev) {
        return 0;
    }

    priv->wifi = wifi_register_device("wlan0", priv, &mt7921_wifi_ops,
                                      priv->macaddr, MT7921_WIFI_MTU,
                                      mt7921_netdev_send, mt7921_netdev_recv);
    if (!priv->wifi) {
        return -ENOMEM;
    }

    priv->rtnl_dev = rtnl_dev_alloc("wlan0", ARPHRD_ETHER);
    if (!priv->rtnl_dev) {
        return -ENOMEM;
    }

    ret = rtnl_dev_register(priv->rtnl_dev);
    if (ret < 0) {
        return ret;
    }

    ret = rtnl_wifi_attach(priv->rtnl_dev, priv->wifi);
    if (ret < 0) {
        rtnl_dev_unregister(priv->rtnl_dev);
        return ret;
    }

    rtnl_notify_link(priv->rtnl_dev, RTM_NEWLINK);
    return 0;
}

void mt7921_wifi_remove(mt7921_priv_t *priv) {
    if (!priv) {
        return;
    }

    priv->removed = true;
    spin_lock(&priv->scan_lock);
    priv->have_target_bss = false;
    memset(&priv->target_bss, 0, sizeof(priv->target_bss));
    spin_unlock(&priv->scan_lock);
    if (priv->wifi) {
        wifi_report_state(priv->wifi, WIFI_STATE_DOWN, 0);
    }
    if (priv->rtnl_dev) {
        rtnl_notify_link(priv->rtnl_dev, RTM_DELLINK);
        rtnl_dev_unregister(priv->rtnl_dev);
    }
}

void mt7921_handle_mcu_event(mt7921_priv_t *priv, const void *data,
                             size_t len) {
    const struct mt7921_mcu_rxd *rxd = (const struct mt7921_mcu_rxd *)data;

    if (!priv || !data || len < sizeof(*rxd) || !priv->wifi) {
        return;
    }

    switch (rxd->eid) {
    case MT7921_MCU_EVENT_SCAN_DONE:
    case MT7921_MCU_EVENT_SCHED_SCAN_DONE:
        mt7921_scan_cache_commit(priv);
        break;
    default:
        break;
    }
}
