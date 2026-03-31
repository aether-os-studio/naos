#include <net/wifi_rtnl.h>

static wifi_device_t *rtnl_wifi_from_dev(struct net_device *dev) {
    if (!dev) {
        return NULL;
    }
    return (wifi_device_t *)dev->wireless_priv;
}

static void rtnl_wifi_apply_status(struct net_device *dev, wifi_device_t *wifi,
                                   const wifi_status_t *status) {
    if (!dev || !wifi || !status) {
        return;
    }

    spin_lock(&dev->lock);

    if (status->state == WIFI_STATE_DOWN) {
        dev->flags &= ~(IFF_UP | IFF_RUNNING | IFF_LOWER_UP);
        dev->operstate = IF_OPER_DOWN;
    } else {
        dev->flags |= IFF_UP;

        if (status->connected || netdev_link_is_up(wifi->netdev)) {
            dev->flags |= IFF_RUNNING | IFF_LOWER_UP;
            dev->operstate = IF_OPER_UP;
        } else {
            dev->flags &= ~(IFF_RUNNING | IFF_LOWER_UP);
            if (status->state == WIFI_STATE_SCANNING ||
                status->state == WIFI_STATE_ASSOCIATING) {
                dev->operstate = IF_OPER_DORMANT;
            } else {
                dev->operstate = IF_OPER_DOWN;
            }
        }
    }

    spin_unlock(&dev->lock);
}

static void rtnl_wifi_event(wifi_device_t *wifi, uint32_t events, void *ctx) {
    struct net_device *dev = (struct net_device *)ctx;
    wifi_status_t status;

    if (!wifi || !dev || !events) {
        return;
    }

    if (wifi_get_status(wifi, &status) < 0) {
        return;
    }

    rtnl_wifi_apply_status(dev, wifi, &status);
    rtnl_notify_link(dev, RTM_NEWLINK);
}

static int rtnl_wifi_link_change(struct net_device *dev, uint32_t old_flags,
                                 uint32_t new_flags) {
    wifi_device_t *wifi = rtnl_wifi_from_dev(dev);
    bool old_up = false;
    bool new_up = false;
    wifi_status_t status;
    int ret = 0;

    if (!wifi) {
        return -ENODEV;
    }

    old_up = !!(old_flags & IFF_UP);
    new_up = !!(new_flags & IFF_UP);
    if (old_up == new_up) {
        return 0;
    }

    if (new_up) {
        if (wifi->ops && wifi->ops->start) {
            ret = wifi->ops->start(wifi);
            if (ret < 0) {
                return ret;
            }
        }
        netdev_set_admin_state(wifi->netdev, true);
        if (wifi_get_status(wifi, &status) == 0 &&
            status.state == WIFI_STATE_DOWN) {
            wifi_report_state(wifi, WIFI_STATE_IDLE, 0);
        }
        return 0;
    }

    if (wifi->ops && wifi->ops->disconnect) {
        (void)wifi->ops->disconnect(wifi);
    }
    if (wifi->ops && wifi->ops->stop) {
        ret = wifi->ops->stop(wifi);
        if (ret < 0) {
            return ret;
        }
    }

    wifi_report_state(wifi, WIFI_STATE_DOWN, 0);
    return 0;
}

static int rtnl_wifi_cmd(struct net_device *dev, const void *data,
                         uint32_t len) {
    wifi_device_t *wifi = rtnl_wifi_from_dev(dev);
    const struct rtnl_wifi_cmd_hdr *hdr =
        (const struct rtnl_wifi_cmd_hdr *)data;
    wifi_connect_params_t params;

    if (!wifi || !hdr) {
        return -EINVAL;
    }
    if (len < sizeof(*hdr) || hdr->magic != RTNL_WIFI_CMD_MAGIC ||
        hdr->version != RTNL_WIFI_CMD_VERSION) {
        return -EINVAL;
    }
    if ((uint32_t)hdr->payload_len + sizeof(*hdr) > len) {
        return -EINVAL;
    }

    switch (hdr->cmd) {
    case RTNL_WIFI_CMD_SET_TX_CTX: {
        const struct rtnl_wifi_set_tx_ctx *cmd =
            (const struct rtnl_wifi_set_tx_ctx *)(hdr + 1);
        wifi_tx_context_t tx_ctx;

        if (hdr->payload_len < sizeof(*cmd)) {
            return -EINVAL;
        }

        tx_ctx.wlan_idx = cmd->wlan_idx;
        tx_ctx.own_mac_idx = cmd->own_mac_idx;
        return wifi_request_set_tx_context(wifi, &tx_ctx);
    }

    case RTNL_WIFI_CMD_SET_BSSID: {
        const struct rtnl_wifi_set_bssid *cmd =
            (const struct rtnl_wifi_set_bssid *)(hdr + 1);

        if (hdr->payload_len < sizeof(*cmd)) {
            return -EINVAL;
        }

        return wifi_request_set_bssid(wifi, cmd->bssid);
    }

    case RTNL_WIFI_CMD_SCAN:
        return wifi_request_scan(wifi);

    case RTNL_WIFI_CMD_CONNECT_OPEN: {
        const struct rtnl_wifi_connect_open *cmd =
            (const struct rtnl_wifi_connect_open *)(hdr + 1);

        if (hdr->payload_len < sizeof(*cmd) ||
            cmd->ssid_len > WIFI_MAX_SSID_LEN) {
            return -EINVAL;
        }

        memset(&params, 0, sizeof(params));
        params.ssid_len = cmd->ssid_len;
        params.auth = WIFI_AUTH_OPEN;
        memcpy(params.ssid, cmd->ssid, params.ssid_len);
        return wifi_request_connect(wifi, &params);
    }

    case RTNL_WIFI_CMD_CONNECT_OPEN_BSSID: {
        const struct rtnl_wifi_connect_open_bssid *cmd =
            (const struct rtnl_wifi_connect_open_bssid *)(hdr + 1);

        if (hdr->payload_len < sizeof(*cmd) ||
            cmd->ssid_len > WIFI_MAX_SSID_LEN) {
            return -EINVAL;
        }

        memset(&params, 0, sizeof(params));
        params.ssid_len = cmd->ssid_len;
        params.auth = WIFI_AUTH_OPEN;
        params.have_bssid = true;
        memcpy(params.bssid, cmd->bssid, sizeof(params.bssid));
        memcpy(params.ssid, cmd->ssid, params.ssid_len);
        return wifi_request_connect(wifi, &params);
    }

    case RTNL_WIFI_CMD_CONNECT: {
        const struct rtnl_wifi_connect *cmd =
            (const struct rtnl_wifi_connect *)(hdr + 1);

        if (hdr->payload_len < sizeof(*cmd) ||
            cmd->ssid_len > WIFI_MAX_SSID_LEN ||
            cmd->credential_len > WIFI_MAX_CREDENTIAL_LEN) {
            return -EINVAL;
        }

        memset(&params, 0, sizeof(params));
        params.ssid_len = cmd->ssid_len;
        params.auth = cmd->auth;
        params.credential_len = cmd->credential_len;
        params.channel_hint = cmd->channel_hint;
        params.have_bssid = !!(cmd->flags & RTNL_WIFI_CONNECT_HAS_BSSID);
        memcpy(params.ssid, cmd->ssid, params.ssid_len);
        memcpy(params.credential, cmd->credential, params.credential_len);
        if (params.have_bssid) {
            memcpy(params.bssid, cmd->bssid, sizeof(params.bssid));
        }
        return wifi_request_connect(wifi, &params);
    }

    case RTNL_WIFI_CMD_DISCONNECT:
        return wifi_request_disconnect(wifi);

    default:
        return -EOPNOTSUPP;
    }
}

static int rtnl_wifi_dump(struct net_device *dev, struct nla_builder *builder) {
    wifi_device_t *wifi = rtnl_wifi_from_dev(dev);
    struct rtnl_wifi_snapshot snapshot;
    wifi_status_t status;
    wifi_bss_info_t scan_results[RTNL_WIFI_SNAPSHOT_MAX_BSS];
    uint32_t count = 0;
    size_t payload_len = 0;

    if (!wifi || !builder) {
        return -EINVAL;
    }
    if (wifi_get_status(wifi, &status) < 0) {
        return -EINVAL;
    }

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = status.state;
    snapshot.auth = status.auth;
    snapshot.last_error = status.last_error;
    snapshot.scan_generation = status.scan_generation;
    snapshot.signal_dbm = status.signal_dbm;
    snapshot.freq_mhz = status.freq_mhz;
    snapshot.ssid_len = status.ssid_len;
    snapshot.wlan_idx = status.tx_ctx.wlan_idx;
    snapshot.own_mac_idx = status.tx_ctx.own_mac_idx;
    memcpy(snapshot.ssid, status.ssid, sizeof(snapshot.ssid));
    if (status.have_bssid) {
        snapshot.flags |= RTNL_WIFI_SNAPSHOT_HAS_BSSID;
        memcpy(snapshot.bssid, status.bssid, sizeof(snapshot.bssid));
    }
    if (status.connected) {
        snapshot.flags |= RTNL_WIFI_SNAPSHOT_CONNECTED;
    }
    if (netdev_admin_is_up(wifi->netdev)) {
        snapshot.flags |= RTNL_WIFI_SNAPSHOT_ADMIN_UP;
    }
    if (netdev_link_is_up(wifi->netdev)) {
        snapshot.flags |= RTNL_WIFI_SNAPSHOT_LINK_UP;
    }

    count =
        wifi_get_scan_results(wifi, scan_results, RTNL_WIFI_SNAPSHOT_MAX_BSS);
    snapshot.num_scan_results = count;

    for (uint32_t i = 0; i < count; i++) {
        snapshot.scan_results[i].ssid_len = scan_results[i].ssid_len;
        snapshot.scan_results[i].channel = scan_results[i].channel;
        snapshot.scan_results[i].freq_mhz = scan_results[i].freq_mhz;
        snapshot.scan_results[i].signal_dbm = scan_results[i].signal_dbm;
        snapshot.scan_results[i].flags = scan_results[i].flags;
        memcpy(snapshot.scan_results[i].bssid, scan_results[i].bssid,
               sizeof(snapshot.scan_results[i].bssid));
        memcpy(snapshot.scan_results[i].ssid, scan_results[i].ssid,
               sizeof(snapshot.scan_results[i].ssid));
    }

    payload_len = sizeof(snapshot) - sizeof(snapshot.scan_results) +
                  count * sizeof(struct rtnl_wifi_scan_result);
    return nla_put(builder, IFLA_WIRELESS, &snapshot, payload_len);
}

int rtnl_wifi_attach(struct net_device *dev, wifi_device_t *wifi) {
    wifi_status_t status;

    if (!dev || !wifi || !wifi->netdev) {
        return -EINVAL;
    }

    memcpy(dev->addr, wifi->netdev->mac, 6);
    dev->addr_len = 6;
    memset(dev->broadcast, 0xFF, 6);
    dev->mtu = wifi->netdev->mtu;

    netdev_set_name(wifi->netdev, dev->name);
    rtnl_dev_set_wireless_ops(dev, wifi, rtnl_wifi_cmd, rtnl_wifi_dump);
    rtnl_dev_set_link_change_handler(dev, rtnl_wifi_link_change);
    if (wifi_register_listener(wifi, rtnl_wifi_event, dev) < 0) {
        return -ENOMEM;
    }

    if (wifi_get_status(wifi, &status) == 0) {
        rtnl_wifi_apply_status(dev, wifi, &status);
    }

    return 0;
}
