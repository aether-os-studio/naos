#pragma once

#include <net/netdev.h>

#define WIFI_MAX_SSID_LEN 32
#define WIFI_MAX_CREDENTIAL_LEN 64
#define WIFI_MAX_SCAN_RESULTS 16
#define WIFI_MAX_EVENT_LISTENERS 8

struct wifi_device;

typedef struct wifi_tx_context {
    uint16_t wlan_idx;
    uint8_t own_mac_idx;
} wifi_tx_context_t;

enum wifi_state {
    WIFI_STATE_DOWN = 0,
    WIFI_STATE_IDLE,
    WIFI_STATE_SCANNING,
    WIFI_STATE_ASSOCIATING,
    WIFI_STATE_CONNECTED,
    WIFI_STATE_DISCONNECTED,
    WIFI_STATE_ERROR,
};

enum wifi_auth_type {
    WIFI_AUTH_OPEN = 0,
    WIFI_AUTH_WPA_PSK = 1,
    WIFI_AUTH_WPA2_PSK = 2,
    WIFI_AUTH_WPA3_SAE = 3,
};

enum wifi_bss_flags {
    WIFI_BSS_FLAG_PRIVACY = 1U << 0,
    WIFI_BSS_FLAG_WPA = 1U << 1,
    WIFI_BSS_FLAG_WPA2 = 1U << 2,
    WIFI_BSS_FLAG_WPA3 = 1U << 3,
    WIFI_BSS_FLAG_HIDDEN = 1U << 4,
};

enum wifi_event_type {
    WIFI_EVENT_STATE_CHANGED = 1U << 0,
    WIFI_EVENT_SCAN_UPDATED = 1U << 1,
    WIFI_EVENT_CONNECTED = 1U << 2,
    WIFI_EVENT_DISCONNECTED = 1U << 3,
    WIFI_EVENT_CONFIG_CHANGED = 1U << 4,
};

typedef struct wifi_bss_info {
    uint8_t bssid[6];
    uint8_t ssid_len;
    uint8_t channel;
    uint16_t freq_mhz;
    int16_t signal_dbm;
    uint32_t flags;
    char ssid[WIFI_MAX_SSID_LEN];
} wifi_bss_info_t;

typedef struct wifi_connect_params {
    uint8_t ssid_len;
    bool have_bssid;
    uint8_t bssid[6];
    uint8_t channel_hint;
    uint8_t credential_len;
    uint32_t auth;
    char ssid[WIFI_MAX_SSID_LEN];
    char credential[WIFI_MAX_CREDENTIAL_LEN];
} wifi_connect_params_t;

typedef struct wifi_status {
    uint32_t state;
    uint32_t auth;
    bool connected;
    bool have_bssid;
    uint8_t bssid[6];
    uint8_t ssid_len;
    uint16_t freq_mhz;
    int16_t signal_dbm;
    uint32_t last_error;
    wifi_tx_context_t tx_ctx;
    uint32_t scan_generation;
    uint32_t num_scan_results;
    char ssid[WIFI_MAX_SSID_LEN];
} wifi_status_t;

typedef void (*wifi_event_cb_t)(struct wifi_device *wifi, uint32_t events,
                                void *ctx);

typedef struct wifi_driver_ops {
    int (*start)(struct wifi_device *wifi);
    int (*stop)(struct wifi_device *wifi);
    int (*scan)(struct wifi_device *wifi);
    int (*connect)(struct wifi_device *wifi,
                   const wifi_connect_params_t *params);
    int (*disconnect)(struct wifi_device *wifi);
    int (*set_tx_context)(struct wifi_device *wifi,
                          const wifi_tx_context_t *tx_ctx);
    int (*set_bssid)(struct wifi_device *wifi, const uint8_t *bssid);
} wifi_driver_ops_t;

typedef struct wifi_event_listener {
    wifi_event_cb_t cb;
    void *ctx;
} wifi_event_listener_t;

typedef struct wifi_device {
    netdev_t *netdev;
    void *drv_priv;
    const wifi_driver_ops_t *ops;
    spinlock_t lock;
    wifi_status_t status;
    wifi_connect_params_t last_connect;
    bool have_last_connect;
    bool have_forced_bssid;
    uint8_t forced_bssid[6];
    wifi_bss_info_t scan_results[WIFI_MAX_SCAN_RESULTS];
    wifi_event_listener_t listeners[WIFI_MAX_EVENT_LISTENERS];
} wifi_device_t;

wifi_device_t *wifi_register_device(const char *name, void *drv_priv,
                                    const wifi_driver_ops_t *ops,
                                    const uint8_t *mac, uint32_t mtu,
                                    netdev_send_t send, netdev_recv_t recv);

int wifi_register_listener(wifi_device_t *wifi, wifi_event_cb_t cb, void *ctx);
void wifi_unregister_listener(wifi_device_t *wifi, wifi_event_cb_t cb,
                              void *ctx);
void wifi_notify(wifi_device_t *wifi, uint32_t events);

int wifi_request_scan(wifi_device_t *wifi);
int wifi_request_connect(wifi_device_t *wifi,
                         const wifi_connect_params_t *params);
int wifi_request_disconnect(wifi_device_t *wifi);
int wifi_request_set_tx_context(wifi_device_t *wifi,
                                const wifi_tx_context_t *tx_ctx);
int wifi_request_set_bssid(wifi_device_t *wifi, const uint8_t *bssid);

void wifi_report_scan_results(wifi_device_t *wifi,
                              const wifi_bss_info_t *results, uint32_t count);
void wifi_report_connected(wifi_device_t *wifi,
                           const wifi_connect_params_t *params,
                           const wifi_bss_info_t *bss);
void wifi_report_disconnected(wifi_device_t *wifi, int error_code);
void wifi_report_state(wifi_device_t *wifi, uint32_t state, int error_code);

int wifi_get_status(wifi_device_t *wifi, wifi_status_t *out_status);
uint32_t wifi_get_scan_results(wifi_device_t *wifi,
                               wifi_bss_info_t *out_results, uint32_t capacity);
