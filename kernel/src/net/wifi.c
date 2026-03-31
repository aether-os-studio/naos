#include <net/wifi.h>
#include <mm/mm.h>

static void wifi_set_state_locked(wifi_device_t *wifi, uint32_t state,
                                  int error_code) {
    wifi->status.state = state;
    wifi->status.last_error = (error_code < 0) ? (uint32_t)(-error_code) : 0;
}

wifi_device_t *wifi_register_device(const char *name, void *drv_priv,
                                    const wifi_driver_ops_t *ops,
                                    const uint8_t *mac, uint32_t mtu,
                                    netdev_send_t send, netdev_recv_t recv) {
    wifi_device_t *wifi = calloc(1, sizeof(*wifi));
    if (!wifi) {
        return NULL;
    }

    wifi->netdev =
        netdev_register(name, NETDEV_TYPE_WIFI, drv_priv, mac, mtu, send, recv);
    if (!wifi->netdev) {
        free(wifi);
        return NULL;
    }

    wifi->drv_priv = drv_priv;
    wifi->ops = ops;
    wifi->lock = SPIN_INIT;
    wifi_set_state_locked(wifi, WIFI_STATE_DOWN, 0);
    wifi->status.auth = WIFI_AUTH_OPEN;
    wifi->status.tx_ctx.wlan_idx = 0;
    wifi->status.tx_ctx.own_mac_idx = 0;

    return wifi;
}

int wifi_register_listener(wifi_device_t *wifi, wifi_event_cb_t cb, void *ctx) {
    if (!wifi || !cb) {
        return -EINVAL;
    }

    spin_lock(&wifi->lock);
    for (uint32_t i = 0; i < WIFI_MAX_EVENT_LISTENERS; i++) {
        if (wifi->listeners[i].cb == NULL) {
            wifi->listeners[i].cb = cb;
            wifi->listeners[i].ctx = ctx;
            spin_unlock(&wifi->lock);
            return 0;
        }
    }
    spin_unlock(&wifi->lock);

    return -ENOSPC;
}

void wifi_unregister_listener(wifi_device_t *wifi, wifi_event_cb_t cb,
                              void *ctx) {
    if (!wifi || !cb) {
        return;
    }

    spin_lock(&wifi->lock);
    for (uint32_t i = 0; i < WIFI_MAX_EVENT_LISTENERS; i++) {
        if (wifi->listeners[i].cb == cb && wifi->listeners[i].ctx == ctx) {
            wifi->listeners[i].cb = NULL;
            wifi->listeners[i].ctx = NULL;
            break;
        }
    }
    spin_unlock(&wifi->lock);
}

void wifi_notify(wifi_device_t *wifi, uint32_t events) {
    wifi_event_listener_t listeners[WIFI_MAX_EVENT_LISTENERS];

    if (!wifi || !events) {
        return;
    }

    spin_lock(&wifi->lock);
    memcpy(listeners, wifi->listeners, sizeof(listeners));
    spin_unlock(&wifi->lock);

    for (uint32_t i = 0; i < WIFI_MAX_EVENT_LISTENERS; i++) {
        if (listeners[i].cb) {
            listeners[i].cb(wifi, events, listeners[i].ctx);
        }
    }
}

int wifi_request_scan(wifi_device_t *wifi) {
    int ret = 0;

    if (!wifi || !wifi->ops || !wifi->ops->scan) {
        return -EOPNOTSUPP;
    }

    if (!netdev_admin_is_up(wifi->netdev)) {
        if (wifi->ops->start) {
            ret = wifi->ops->start(wifi);
            if (ret < 0) {
                spin_lock(&wifi->lock);
                wifi_set_state_locked(wifi, WIFI_STATE_ERROR, ret);
                spin_unlock(&wifi->lock);
                wifi_notify(wifi, WIFI_EVENT_STATE_CHANGED);
                return ret;
            }
        }
        netdev_set_admin_state(wifi->netdev, true);
    }

    spin_lock(&wifi->lock);
    wifi_set_state_locked(wifi, WIFI_STATE_SCANNING, 0);
    spin_unlock(&wifi->lock);

    wifi_notify(wifi, WIFI_EVENT_STATE_CHANGED);
    ret = wifi->ops->scan(wifi);
    if (ret < 0) {
        spin_lock(&wifi->lock);
        wifi_set_state_locked(wifi, WIFI_STATE_ERROR, ret);
        spin_unlock(&wifi->lock);
        wifi_notify(wifi, WIFI_EVENT_STATE_CHANGED);
    }

    return ret;
}

int wifi_request_connect(wifi_device_t *wifi,
                         const wifi_connect_params_t *params) {
    int ret = 0;
    wifi_connect_params_t effective;

    if (!wifi || !params || !wifi->ops || !wifi->ops->connect) {
        return -EOPNOTSUPP;
    }

    memset(&effective, 0, sizeof(effective));
    memcpy(&effective, params, sizeof(effective));

    spin_lock(&wifi->lock);
    if (!effective.have_bssid && wifi->have_forced_bssid) {
        memcpy(effective.bssid, wifi->forced_bssid, sizeof(effective.bssid));
        effective.have_bssid = true;
    }
    memcpy(&wifi->last_connect, &effective, sizeof(wifi->last_connect));
    wifi->have_last_connect = true;
    wifi_set_state_locked(wifi, WIFI_STATE_ASSOCIATING, 0);
    wifi->status.auth = effective.auth;
    spin_unlock(&wifi->lock);

    if (!netdev_admin_is_up(wifi->netdev)) {
        if (wifi->ops->start) {
            ret = wifi->ops->start(wifi);
            if (ret < 0) {
                spin_lock(&wifi->lock);
                wifi_set_state_locked(wifi, WIFI_STATE_ERROR, ret);
                spin_unlock(&wifi->lock);
                wifi_notify(wifi, WIFI_EVENT_STATE_CHANGED);
                return ret;
            }
        }
        netdev_set_admin_state(wifi->netdev, true);
    }

    wifi_notify(wifi, WIFI_EVENT_STATE_CHANGED);

    ret = wifi->ops->connect(wifi, &effective);
    if (ret < 0) {
        spin_lock(&wifi->lock);
        wifi_set_state_locked(wifi, WIFI_STATE_ERROR, ret);
        spin_unlock(&wifi->lock);
        wifi_notify(wifi, WIFI_EVENT_STATE_CHANGED);
    }

    return ret;
}

int wifi_request_disconnect(wifi_device_t *wifi) {
    int ret = 0;

    if (!wifi || !wifi->ops || !wifi->ops->disconnect) {
        return -EOPNOTSUPP;
    }

    ret = wifi->ops->disconnect(wifi);
    if (ret < 0) {
        spin_lock(&wifi->lock);
        wifi_set_state_locked(wifi, WIFI_STATE_ERROR, ret);
        spin_unlock(&wifi->lock);
        wifi_notify(wifi, WIFI_EVENT_STATE_CHANGED);
        return ret;
    }

    wifi_report_disconnected(wifi, 0);
    return 0;
}

int wifi_request_set_tx_context(wifi_device_t *wifi,
                                const wifi_tx_context_t *tx_ctx) {
    int ret = 0;

    if (!wifi || !tx_ctx) {
        return -EINVAL;
    }

    if (wifi->ops && wifi->ops->set_tx_context) {
        ret = wifi->ops->set_tx_context(wifi, tx_ctx);
        if (ret < 0) {
            return ret;
        }
    }

    spin_lock(&wifi->lock);
    wifi->status.tx_ctx = *tx_ctx;
    spin_unlock(&wifi->lock);
    wifi_notify(wifi, WIFI_EVENT_CONFIG_CHANGED);

    return 0;
}

int wifi_request_set_bssid(wifi_device_t *wifi, const uint8_t *bssid) {
    int ret = 0;

    if (!wifi || !bssid) {
        return -EINVAL;
    }

    if (wifi->ops && wifi->ops->set_bssid) {
        ret = wifi->ops->set_bssid(wifi, bssid);
        if (ret < 0) {
            return ret;
        }
    }

    spin_lock(&wifi->lock);
    memcpy(wifi->forced_bssid, bssid, sizeof(wifi->forced_bssid));
    wifi->have_forced_bssid = true;
    spin_unlock(&wifi->lock);
    wifi_notify(wifi, WIFI_EVENT_CONFIG_CHANGED);

    return 0;
}

void wifi_report_scan_results(wifi_device_t *wifi,
                              const wifi_bss_info_t *results, uint32_t count) {
    uint32_t to_copy = 0;

    if (!wifi) {
        return;
    }

    to_copy = MIN(count, (uint32_t)WIFI_MAX_SCAN_RESULTS);

    spin_lock(&wifi->lock);
    memset(wifi->scan_results, 0, sizeof(wifi->scan_results));
    if (results && to_copy > 0) {
        memcpy(wifi->scan_results, results, to_copy * sizeof(*results));
    }
    wifi->status.num_scan_results = to_copy;
    wifi->status.scan_generation++;
    if (wifi->status.connected) {
        wifi_set_state_locked(wifi, WIFI_STATE_CONNECTED, 0);
    } else {
        wifi_set_state_locked(wifi, WIFI_STATE_IDLE, 0);
    }
    spin_unlock(&wifi->lock);

    wifi_notify(wifi, WIFI_EVENT_SCAN_UPDATED | WIFI_EVENT_STATE_CHANGED);
}

void wifi_report_connected(wifi_device_t *wifi,
                           const wifi_connect_params_t *params,
                           const wifi_bss_info_t *bss) {
    if (!wifi) {
        return;
    }

    spin_lock(&wifi->lock);
    wifi->status.connected = true;
    wifi->status.have_bssid = false;
    wifi->status.signal_dbm = 0;
    wifi->status.freq_mhz = 0;
    if (params) {
        memcpy(&wifi->last_connect, params, sizeof(wifi->last_connect));
        wifi->have_last_connect = true;
        memcpy(wifi->status.ssid, params->ssid, sizeof(wifi->status.ssid));
        wifi->status.ssid_len =
            MIN((uint32_t)params->ssid_len, (uint32_t)WIFI_MAX_SSID_LEN);
        wifi->status.auth = params->auth;
        if (params->have_bssid) {
            memcpy(wifi->status.bssid, params->bssid,
                   sizeof(wifi->status.bssid));
            wifi->status.have_bssid = true;
        }
    }
    if (bss) {
        memcpy(wifi->status.ssid, bss->ssid, sizeof(wifi->status.ssid));
        wifi->status.ssid_len =
            MIN((uint32_t)bss->ssid_len, (uint32_t)WIFI_MAX_SSID_LEN);
        memcpy(wifi->status.bssid, bss->bssid, sizeof(wifi->status.bssid));
        wifi->status.have_bssid = true;
        wifi->status.signal_dbm = bss->signal_dbm;
        wifi->status.freq_mhz = bss->freq_mhz;
    }
    wifi_set_state_locked(wifi, WIFI_STATE_CONNECTED, 0);
    spin_unlock(&wifi->lock);

    netdev_set_admin_state(wifi->netdev, true);
    netdev_set_link_state(wifi->netdev, true);
    wifi_notify(wifi, WIFI_EVENT_CONNECTED | WIFI_EVENT_STATE_CHANGED);
}

void wifi_report_disconnected(wifi_device_t *wifi, int error_code) {
    if (!wifi) {
        return;
    }

    spin_lock(&wifi->lock);
    wifi->status.connected = false;
    wifi->status.have_bssid = false;
    memset(wifi->status.bssid, 0, sizeof(wifi->status.bssid));
    wifi->status.signal_dbm = 0;
    wifi->status.freq_mhz = 0;
    wifi_set_state_locked(wifi, WIFI_STATE_DISCONNECTED, error_code);
    spin_unlock(&wifi->lock);

    netdev_set_link_state(wifi->netdev, false);
    wifi_notify(wifi, WIFI_EVENT_DISCONNECTED | WIFI_EVENT_STATE_CHANGED);
}

void wifi_report_state(wifi_device_t *wifi, uint32_t state, int error_code) {
    if (!wifi) {
        return;
    }

    spin_lock(&wifi->lock);
    wifi_set_state_locked(wifi, state, error_code);
    spin_unlock(&wifi->lock);

    if (state == WIFI_STATE_DOWN) {
        netdev_set_admin_state(wifi->netdev, false);
        netdev_set_link_state(wifi->netdev, false);
    }

    wifi_notify(wifi, WIFI_EVENT_STATE_CHANGED);
}

int wifi_get_status(wifi_device_t *wifi, wifi_status_t *out_status) {
    if (!wifi || !out_status) {
        return -EINVAL;
    }

    spin_lock(&wifi->lock);
    *out_status = wifi->status;
    spin_unlock(&wifi->lock);
    return 0;
}

uint32_t wifi_get_scan_results(wifi_device_t *wifi,
                               wifi_bss_info_t *out_results,
                               uint32_t capacity) {
    uint32_t to_copy = 0;

    if (!wifi) {
        return 0;
    }

    spin_lock(&wifi->lock);
    to_copy = MIN(capacity, wifi->status.num_scan_results);
    if (out_results && to_copy > 0) {
        memcpy(out_results, wifi->scan_results, to_copy * sizeof(*out_results));
    }
    spin_unlock(&wifi->lock);

    return to_copy;
}
