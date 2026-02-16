#pragma once

#include <libs/klibc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEEE80211_ADDR_LEN 6
#define IEEE80211_ETH_HDR_LEN 14
#define IEEE80211_DATA_HDR_LEN 24
#define IEEE80211_LLC_SNAP_LEN 8
#define IEEE80211_MAX_FRAME_LEN 2304

typedef int (*ieee80211_tx_raw_t)(void *driver, const void *buf, uint32_t len);
typedef int (*ieee80211_rx_raw_t)(void *driver, void *buf, uint32_t len);

typedef struct ieee80211_ctx {
    uint8_t sta_addr[IEEE80211_ADDR_LEN];
    uint8_t bssid[IEEE80211_ADDR_LEN];
    uint16_t seq_ctrl;
    bool has_bssid;
} ieee80211_ctx_t;

typedef struct ieee80211_netif {
    void *driver_priv;
    ieee80211_tx_raw_t tx_raw;
    ieee80211_rx_raw_t rx_raw;
    ieee80211_ctx_t ctx;
} ieee80211_netif_t;

typedef struct ieee80211_rx_info {
    uint8_t type;
    uint8_t subtype;
    bool to_ds;
    bool from_ds;
    bool protected_frame;
} ieee80211_rx_info_t;

void ieee80211_ctx_init(ieee80211_ctx_t *ctx,
                        const uint8_t sta_addr[IEEE80211_ADDR_LEN]);
void ieee80211_ctx_set_bssid(ieee80211_ctx_t *ctx,
                             const uint8_t bssid[IEEE80211_ADDR_LEN]);
void ieee80211_ctx_clear_bssid(ieee80211_ctx_t *ctx);

int ieee80211_parse_rx_info(const void *frame, uint32_t frame_len,
                            ieee80211_rx_info_t *info);

int ieee80211_encap_eth_data(ieee80211_ctx_t *ctx, const void *eth_frame,
                             uint32_t eth_len, void *out_frame,
                             uint32_t out_capacity, uint32_t *out_len);

int ieee80211_decap_eth_data(const void *wifi_frame, uint32_t wifi_len,
                             void *out_eth_frame, uint32_t out_capacity,
                             uint32_t *out_len);

int ieee80211_parse_beacon_ssid(const void *frame, uint32_t frame_len,
                                char *ssid, uint32_t ssid_capacity,
                                uint8_t *channel);

int ieee80211_netif_init(ieee80211_netif_t *iface, void *driver_priv,
                         ieee80211_tx_raw_t tx_raw, ieee80211_rx_raw_t rx_raw,
                         const uint8_t sta_addr[IEEE80211_ADDR_LEN]);

int ieee80211_netif_send_eth(ieee80211_netif_t *iface, const void *eth_frame,
                             uint32_t eth_len);

int ieee80211_netif_recv_eth(ieee80211_netif_t *iface, void *out_eth_frame,
                             uint32_t out_capacity);

#ifdef __cplusplus
}
#endif
