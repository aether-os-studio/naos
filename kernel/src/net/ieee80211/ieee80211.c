#include <net/ieee80211/ieee80211.h>

#define IEEE80211_FC_TYPE_MASK 0x000c
#define IEEE80211_FC_SUBTYPE_MASK 0x00f0
#define IEEE80211_FC_TYPE_DATA 0x0008
#define IEEE80211_FC_TYPE_MGMT 0x0000
#define IEEE80211_FC_SUBTYPE_BEACON 0x0080
#define IEEE80211_FC_TO_DS 0x0100
#define IEEE80211_FC_FROM_DS 0x0200
#define IEEE80211_FC_PROTECTED 0x4000

#define IEEE80211_ADDR1_OFF 4
#define IEEE80211_ADDR2_OFF 10
#define IEEE80211_ADDR3_OFF 16
#define IEEE80211_SEQ_CTRL_OFF 22

#define IEEE80211_LLC_DSAP 0xaa
#define IEEE80211_LLC_SSAP 0xaa
#define IEEE80211_LLC_CTRL 0x03

#define IEEE80211_IE_ID_SSID 0
#define IEEE80211_IE_ID_DS_PARAM 3

struct ieee80211_hdr_min {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[IEEE80211_ADDR_LEN];
    uint8_t addr2[IEEE80211_ADDR_LEN];
    uint8_t addr3[IEEE80211_ADDR_LEN];
    uint16_t seq_ctrl;
} __attribute__((packed));

static uint16_t load_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void store_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}

void ieee80211_ctx_init(ieee80211_ctx_t *ctx,
                        const uint8_t sta_addr[IEEE80211_ADDR_LEN]) {
    if (!ctx || !sta_addr) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->sta_addr, sta_addr, IEEE80211_ADDR_LEN);
}

void ieee80211_ctx_set_bssid(ieee80211_ctx_t *ctx,
                             const uint8_t bssid[IEEE80211_ADDR_LEN]) {
    if (!ctx || !bssid) {
        return;
    }

    memcpy(ctx->bssid, bssid, IEEE80211_ADDR_LEN);
    ctx->has_bssid = true;
}

void ieee80211_ctx_clear_bssid(ieee80211_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    memset(ctx->bssid, 0, IEEE80211_ADDR_LEN);
    ctx->has_bssid = false;
}

int ieee80211_parse_rx_info(const void *frame, uint32_t frame_len,
                            ieee80211_rx_info_t *info) {
    if (!frame || !info) {
        return -EINVAL;
    }
    if (frame_len < IEEE80211_DATA_HDR_LEN) {
        return -EINVAL;
    }

    const uint8_t *bytes = (const uint8_t *)frame;
    uint16_t fc = load_le16(bytes);

    info->type = (uint8_t)((fc & IEEE80211_FC_TYPE_MASK) >> 2);
    info->subtype = (uint8_t)((fc & IEEE80211_FC_SUBTYPE_MASK) >> 4);
    info->to_ds = (fc & IEEE80211_FC_TO_DS) != 0;
    info->from_ds = (fc & IEEE80211_FC_FROM_DS) != 0;
    info->protected_frame = (fc & IEEE80211_FC_PROTECTED) != 0;

    return 0;
}

int ieee80211_encap_eth_data(ieee80211_ctx_t *ctx, const void *eth_frame,
                             uint32_t eth_len, void *out_frame,
                             uint32_t out_capacity, uint32_t *out_len) {
    if (!ctx || !eth_frame || !out_frame || !out_len) {
        return -EINVAL;
    }
    if (!ctx->has_bssid) {
        return -ENOTCONN;
    }
    if (eth_len < IEEE80211_ETH_HDR_LEN) {
        return -EINVAL;
    }

    const uint8_t *eth = (const uint8_t *)eth_frame;
    uint32_t payload_len = eth_len - IEEE80211_ETH_HDR_LEN;
    uint32_t frame_len =
        IEEE80211_DATA_HDR_LEN + IEEE80211_LLC_SNAP_LEN + payload_len;

    if (out_capacity < frame_len) {
        return -ENOSPC;
    }

    uint8_t *out = (uint8_t *)out_frame;
    memset(out, 0, frame_len);

    store_le16(out, (uint16_t)(IEEE80211_FC_TYPE_DATA | IEEE80211_FC_TO_DS));
    store_le16(out + 2, 0);

    memcpy(out + IEEE80211_ADDR1_OFF, ctx->bssid, IEEE80211_ADDR_LEN);
    memcpy(out + IEEE80211_ADDR2_OFF, ctx->sta_addr, IEEE80211_ADDR_LEN);
    memcpy(out + IEEE80211_ADDR3_OFF, eth, IEEE80211_ADDR_LEN);

    store_le16(out + IEEE80211_SEQ_CTRL_OFF,
               (uint16_t)((ctx->seq_ctrl & 0x0fff) << 4));
    ctx->seq_ctrl = (uint16_t)((ctx->seq_ctrl + 1) & 0x0fff);

    uint8_t *llc = out + IEEE80211_DATA_HDR_LEN;
    llc[0] = IEEE80211_LLC_DSAP;
    llc[1] = IEEE80211_LLC_SSAP;
    llc[2] = IEEE80211_LLC_CTRL;
    llc[3] = 0x00;
    llc[4] = 0x00;
    llc[5] = 0x00;

    llc[6] = eth[12];
    llc[7] = eth[13];

    memcpy(out + IEEE80211_DATA_HDR_LEN + IEEE80211_LLC_SNAP_LEN,
           eth + IEEE80211_ETH_HDR_LEN, payload_len);

    *out_len = frame_len;
    return 0;
}

int ieee80211_decap_eth_data(const void *wifi_frame, uint32_t wifi_len,
                             void *out_eth_frame, uint32_t out_capacity,
                             uint32_t *out_len) {
    if (!wifi_frame || !out_eth_frame || !out_len) {
        return -EINVAL;
    }

    if (wifi_len < IEEE80211_DATA_HDR_LEN + IEEE80211_LLC_SNAP_LEN) {
        return -EINVAL;
    }

    const uint8_t *in = (const uint8_t *)wifi_frame;
    uint16_t fc = load_le16(in);
    uint16_t type = fc & IEEE80211_FC_TYPE_MASK;

    if (type != IEEE80211_FC_TYPE_DATA) {
        return -EOPNOTSUPP;
    }

    bool to_ds = (fc & IEEE80211_FC_TO_DS) != 0;
    bool from_ds = (fc & IEEE80211_FC_FROM_DS) != 0;
    if (to_ds && from_ds) {
        return -EOPNOTSUPP;
    }

    uint8_t subtype = (uint8_t)(fc & IEEE80211_FC_SUBTYPE_MASK);
    uint32_t hdr_len = IEEE80211_DATA_HDR_LEN;

    if (subtype >= 0x80) {
        hdr_len += 2;
    }

    if (wifi_len < hdr_len + IEEE80211_LLC_SNAP_LEN) {
        return -EINVAL;
    }

    const uint8_t *llc = in + hdr_len;
    if (llc[0] != IEEE80211_LLC_DSAP || llc[1] != IEEE80211_LLC_SSAP ||
        llc[2] != IEEE80211_LLC_CTRL) {
        return -EOPNOTSUPP;
    }

    uint32_t payload_len = wifi_len - hdr_len - IEEE80211_LLC_SNAP_LEN;
    uint32_t eth_len = IEEE80211_ETH_HDR_LEN + payload_len;
    if (out_capacity < eth_len) {
        return -ENOSPC;
    }

    uint8_t *eth = (uint8_t *)out_eth_frame;

    const uint8_t *da;
    const uint8_t *sa;

    if (to_ds) {
        da = in + IEEE80211_ADDR3_OFF;
        sa = in + IEEE80211_ADDR2_OFF;
    } else if (from_ds) {
        da = in + IEEE80211_ADDR1_OFF;
        sa = in + IEEE80211_ADDR3_OFF;
    } else {
        da = in + IEEE80211_ADDR1_OFF;
        sa = in + IEEE80211_ADDR2_OFF;
    }

    memcpy(eth, da, IEEE80211_ADDR_LEN);
    memcpy(eth + IEEE80211_ADDR_LEN, sa, IEEE80211_ADDR_LEN);

    eth[12] = llc[6];
    eth[13] = llc[7];

    memcpy(eth + IEEE80211_ETH_HDR_LEN, in + hdr_len + IEEE80211_LLC_SNAP_LEN,
           payload_len);

    *out_len = eth_len;
    return 0;
}

int ieee80211_parse_beacon_ssid(const void *frame, uint32_t frame_len,
                                char *ssid, uint32_t ssid_capacity,
                                uint8_t *channel) {
    if (!frame || !ssid || ssid_capacity == 0) {
        return -EINVAL;
    }

    if (frame_len < IEEE80211_DATA_HDR_LEN + 12) {
        return -EINVAL;
    }

    const uint8_t *in = (const uint8_t *)frame;
    uint16_t fc = load_le16(in);

    if ((fc & IEEE80211_FC_TYPE_MASK) != IEEE80211_FC_TYPE_MGMT ||
        (fc & IEEE80211_FC_SUBTYPE_MASK) != IEEE80211_FC_SUBTYPE_BEACON) {
        return -EOPNOTSUPP;
    }

    uint32_t offset = IEEE80211_DATA_HDR_LEN + 12;
    bool ssid_found = false;

    if (channel) {
        *channel = 0;
    }

    while (offset + 2 <= frame_len) {
        uint8_t id = in[offset];
        uint8_t len = in[offset + 1];
        offset += 2;

        if (offset + len > frame_len) {
            break;
        }

        if (id == IEEE80211_IE_ID_SSID) {
            uint32_t copy_len = len;
            if (copy_len >= ssid_capacity) {
                copy_len = ssid_capacity - 1;
            }
            memcpy(ssid, in + offset, copy_len);
            ssid[copy_len] = '\0';
            ssid_found = true;
        } else if (id == IEEE80211_IE_ID_DS_PARAM && len >= 1 && channel) {
            *channel = in[offset];
        }

        offset += len;
    }

    if (!ssid_found) {
        return -ENOENT;
    }

    return 0;
}

int ieee80211_netif_init(ieee80211_netif_t *iface, void *driver_priv,
                         ieee80211_tx_raw_t tx_raw, ieee80211_rx_raw_t rx_raw,
                         const uint8_t sta_addr[IEEE80211_ADDR_LEN]) {
    if (!iface || !tx_raw || !rx_raw || !sta_addr) {
        return -EINVAL;
    }

    memset(iface, 0, sizeof(*iface));
    iface->driver_priv = driver_priv;
    iface->tx_raw = tx_raw;
    iface->rx_raw = rx_raw;
    ieee80211_ctx_init(&iface->ctx, sta_addr);

    return 0;
}

int ieee80211_netif_send_eth(ieee80211_netif_t *iface, const void *eth_frame,
                             uint32_t eth_len) {
    if (!iface || !iface->tx_raw || !eth_frame) {
        return -EINVAL;
    }

    uint8_t tx_buf[IEEE80211_MAX_FRAME_LEN];
    uint32_t tx_len = 0;

    int ret = ieee80211_encap_eth_data(&iface->ctx, eth_frame, eth_len, tx_buf,
                                       sizeof(tx_buf), &tx_len);
    if (ret < 0) {
        return ret;
    }

    return iface->tx_raw(iface->driver_priv, tx_buf, tx_len);
}

int ieee80211_netif_recv_eth(ieee80211_netif_t *iface, void *out_eth_frame,
                             uint32_t out_capacity) {
    if (!iface || !iface->rx_raw || !out_eth_frame) {
        return -EINVAL;
    }

    uint8_t rx_buf[IEEE80211_MAX_FRAME_LEN];
    int in_len = iface->rx_raw(iface->driver_priv, rx_buf, sizeof(rx_buf));

    if (in_len <= 0) {
        return in_len;
    }

    uint32_t out_len = 0;
    int ret = ieee80211_decap_eth_data(rx_buf, (uint32_t)in_len, out_eth_frame,
                                       out_capacity, &out_len);
    if (ret < 0) {
        return ret;
    }

    return (int)out_len;
}
