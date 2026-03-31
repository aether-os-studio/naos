#include "mt7921.h"

#include <mm/mm.h>

static void mt7921_queue_purge(mt7921_queue_entry_t *entries, size_t *count) {
    size_t i;

    for (i = 0; i < *count; i++) {
        free(entries[i].data);
        entries[i].data = NULL;
        entries[i].len = 0;
    }

    *count = 0;
}

static int mt7921_queue_push(mt7921_queue_entry_t *entries, size_t *count,
                             size_t depth, const void *data, size_t len) {
    uint8_t *copy;
    size_t i;

    if (!len || !data) {
        return -EINVAL;
    }

    copy = malloc(len);
    if (!copy) {
        return -ENOMEM;
    }

    memcpy(copy, data, len);

    if (*count == depth) {
        free(entries[0].data);
        for (i = 1; i < *count; i++) {
            entries[i - 1] = entries[i];
        }
        (*count)--;
    }

    entries[*count].data = copy;
    entries[*count].len = len;
    (*count)++;
    return 0;
}

static bool mt7921_resp_pop_by_seq(mt7921_priv_t *priv, uint8_t seq,
                                   uint8_t **data, size_t *len) {
    size_t i;
    bool found = false;

    spin_lock(&priv->resp_lock);
    for (i = 0; i < priv->resp_q_count; i++) {
        struct mt7921_mcu_rxd *rxd;

        if (!priv->resp_q[i].data ||
            priv->resp_q[i].len < sizeof(struct mt7921_mcu_rxd)) {
            continue;
        }

        rxd = (struct mt7921_mcu_rxd *)priv->resp_q[i].data;
        if (rxd->seq != seq) {
            continue;
        }

        *data = priv->resp_q[i].data;
        *len = priv->resp_q[i].len;
        for (; i + 1 < priv->resp_q_count; i++) {
            priv->resp_q[i] = priv->resp_q[i + 1];
        }
        priv->resp_q_count--;
        found = true;
        break;
    }
    spin_unlock(&priv->resp_lock);

    return found;
}

int mt7921_data_pop(mt7921_priv_t *priv, uint8_t **data, size_t *len) {
    bool found = false;

    if (!priv || !data || !len) {
        return -EINVAL;
    }

    *data = NULL;
    *len = 0;

    spin_lock(&priv->data_lock);
    if (priv->data_q_count > 0 && priv->data_q[0].data &&
        priv->data_q[0].len > 0) {
        *data = priv->data_q[0].data;
        *len = priv->data_q[0].len;
        for (size_t i = 1; i < priv->data_q_count; i++) {
            priv->data_q[i - 1] = priv->data_q[i];
        }
        priv->data_q_count--;
        found = true;
    }
    spin_unlock(&priv->data_lock);

    return found ? 0 : -EAGAIN;
}

static void mt7921_resp_push(mt7921_priv_t *priv, const void *data,
                             size_t len) {
    spin_lock(&priv->resp_lock);
    mt7921_queue_push(priv->resp_q, &priv->resp_q_count,
                      MT7921_RESP_QUEUE_DEPTH, data, len);
    spin_unlock(&priv->resp_lock);
}

static void mt7921_data_push(mt7921_priv_t *priv, const void *data,
                             size_t len) {
    spin_lock(&priv->data_lock);
    mt7921_queue_push(priv->data_q, &priv->data_q_count,
                      MT7921_DATA_QUEUE_DEPTH, data, len);
    spin_unlock(&priv->data_lock);
}

static bool mt7921_is_bulk_in(const usb_endpoint_descriptor_t *ep) {
    return ep &&
           (ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
               USB_ENDPOINT_XFER_BULK &&
           (ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN;
}

static bool mt7921_is_bulk_out(const usb_endpoint_descriptor_t *ep) {
    return ep &&
           (ep->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) ==
               USB_ENDPOINT_XFER_BULK &&
           (ep->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_OUT;
}

static int mt7921_usb_collect_endpoints(mt7921_priv_t *priv,
                                        usb_device_interface_t *iface) {
    uint8_t *ptr = (uint8_t *)iface->iface + iface->iface->bLength;
    uint8_t *end = (uint8_t *)iface->end;
    int in_ep = 0;
    int out_ep = 0;

    while (ptr && ptr + 2 <= end) {
        uint8_t len = ptr[0];
        uint8_t type = ptr[1];

        if (len < 2) {
            break;
        }
        if (type == USB_DT_INTERFACE) {
            break;
        }

        if (type == USB_DT_ENDPOINT) {
            usb_endpoint_descriptor_t *ep = (usb_endpoint_descriptor_t *)ptr;
            usb_super_speed_endpoint_descriptor_t *ss = NULL;
            uint8_t *next = ptr + len;

            if (next + 2 <= end && next[1] == USB_DT_ENDPOINT_COMPANION) {
                ss = (usb_super_speed_endpoint_descriptor_t *)next;
            }

            if (mt7921_is_bulk_in(ep) && in_ep < MT7921_USB_IN_MAX) {
                priv->in_ep[in_ep].desc = ep;
                priv->in_ep[in_ep].ss_desc = ss;
                in_ep++;
            } else if (mt7921_is_bulk_out(ep) && out_ep < MT7921_USB_OUT_MAX) {
                priv->out_ep[out_ep].desc = ep;
                priv->out_ep[out_ep].ss_desc = ss;
                out_ep++;
            }
        }

        ptr += len;
    }

    if (in_ep != MT7921_USB_IN_MAX || out_ep != MT7921_USB_OUT_MAX) {
        printk("mt7921: endpoint layout mismatch, got %d IN and %d OUT\n",
               in_ep, out_ep);
        return -EINVAL;
    }

    return 0;
}

static void mt7921_usb_free_pipes(mt7921_priv_t *priv) {
    int i;

    for (i = 0; i < MT7921_USB_IN_MAX; i++) {
        if (priv->in_pipe[i]) {
            usb_free_pipe(priv->usbdev, priv->in_pipe[i]);
            priv->in_pipe[i] = NULL;
        }
    }

    for (i = 0; i < MT7921_USB_OUT_MAX; i++) {
        if (priv->out_pipe[i]) {
            usb_free_pipe(priv->usbdev, priv->out_pipe[i]);
            priv->out_pipe[i] = NULL;
        }
    }
}

static int mt7921_usb_alloc_pipes(mt7921_priv_t *priv) {
    int i;

    for (i = 0; i < MT7921_USB_IN_MAX; i++) {
        priv->in_pipe[i] = usb_alloc_pipe(priv->usbdev, priv->in_ep[i].desc,
                                          priv->in_ep[i].ss_desc);
        if (!priv->in_pipe[i]) {
            return -ENOMEM;
        }
    }

    for (i = 0; i < MT7921_USB_OUT_MAX; i++) {
        priv->out_pipe[i] = usb_alloc_pipe(priv->usbdev, priv->out_ep[i].desc,
                                           priv->out_ep[i].ss_desc);
        if (!priv->out_pipe[i]) {
            return -ENOMEM;
        }
    }

    return 0;
}

static size_t mt7921_usb_frame_len(const uint8_t *buf, size_t buf_size) {
    uint32_t rxd0;
    size_t len;

    if (!buf || buf_size < sizeof(uint32_t)) {
        return 0;
    }

    memcpy(&rxd0, buf, sizeof(rxd0));
    len = (size_t)(rxd0 & MT_RXD0_LENGTH_MASK);
    if (!len || len > buf_size) {
        return 0;
    }

    return len;
}

static void mt7921_usb_handle_cmd_rx(mt7921_priv_t *priv, const void *data,
                                     size_t len) {
    const struct mt7921_mcu_rxd *rxd;

    if (len < sizeof(*rxd)) {
        return;
    }

    rxd = (const struct mt7921_mcu_rxd *)data;
    if (!rxd->seq) {
        mt7921_handle_mcu_event(priv, data, len);
        return;
    }

    mt7921_resp_push(priv, data, len);
}

static void mt7921_usb_handle_data_rx(mt7921_priv_t *priv, const void *data,
                                      size_t len) {
    uint32_t rxd0;
    uint32_t pkt_type;
    uint32_t pkt_flag;
    const struct mt7921_mcu_rxd *rxd;

    if (len < sizeof(uint32_t)) {
        return;
    }

    memcpy(&rxd0, data, sizeof(rxd0));
    pkt_type = (rxd0 & MT_RXD0_PKT_TYPE_MASK) >> MT_RXD0_PKT_TYPE_SHIFT;
    pkt_flag = (rxd0 & MT_RXD0_PKT_FLAG_MASK) >> MT_RXD0_PKT_FLAG_SHIFT;

    if (pkt_type == MT7921_PKT_TYPE_RX_EVENT && pkt_flag == 0x1) {
        pkt_type = MT7921_PKT_TYPE_NORMAL_MCU;
    } else if (pkt_type == MT7921_PKT_TYPE_RX_EVENT &&
               len >= sizeof(struct mt7921_mcu_rxd)) {
        rxd = (const struct mt7921_mcu_rxd *)data;
        if (rxd->seq) {
            mt7921_resp_push(priv, data, len);
        } else {
            mt7921_handle_mcu_event(priv, data, len);
        }
        return;
    }

    if (pkt_type == MT7921_PKT_TYPE_NORMAL ||
        pkt_type == MT7921_PKT_TYPE_NORMAL_MCU) {
        mt7921_data_push(priv, data, len);
    }
}

static void mt7921_rx_worker(uint64_t arg) {
    mt7921_rx_channel_t *chan = (mt7921_rx_channel_t *)arg;
    mt7921_priv_t *priv = chan->priv;

    while (priv->running && chan->enabled) {
        int ret;
        size_t len;

        memset(chan->buffer, 0, chan->buffer_size);
        ret = usb_send_pipe(chan->pipe, USB_DIR_IN, NULL, chan->buffer,
                            (int)chan->buffer_size, MT7921_USB_RX_TIMEOUT_NS);
        if (!priv->running || !chan->enabled) {
            break;
        }
        if (ret != 0) {
            task_block(current_task, TASK_BLOCKING, 1000000, "mt7921_rx");
            continue;
        }

        len = mt7921_usb_frame_len(chan->buffer, chan->buffer_size);
        if (!len) {
            continue;
        }

        if (chan->is_cmd) {
            mt7921_usb_handle_cmd_rx(priv, chan->buffer, len);
        } else {
            mt7921_usb_handle_data_rx(priv, chan->buffer, len);
        }
    }

    __atomic_sub_fetch(&priv->rx_workers, 1, __ATOMIC_RELEASE);
    task_exit(0);
}

int mt7921_usb_init(mt7921_priv_t *priv, usb_device_interface_t *iface) {
    int ret;

    priv->iface = iface;
    ret = mt7921_usb_collect_endpoints(priv, iface);
    if (ret) {
        return ret;
    }

    ret = mt7921_usb_alloc_pipes(priv);
    if (ret) {
        mt7921_usb_free_pipes(priv);
        return ret;
    }

    return 0;
}

void mt7921_usb_cleanup(mt7921_priv_t *priv) {
    if (!priv) {
        return;
    }

    spin_lock(&priv->resp_lock);
    mt7921_queue_purge(priv->resp_q, &priv->resp_q_count);
    spin_unlock(&priv->resp_lock);

    spin_lock(&priv->data_lock);
    mt7921_queue_purge(priv->data_q, &priv->data_q_count);
    spin_unlock(&priv->data_lock);

    mt7921_usb_free_pipes(priv);
}

int mt7921_usb_start_rx(mt7921_priv_t *priv) {
    uint64_t wait_deadline;

    priv->running = true;

    priv->data_rx.priv = priv;
    priv->data_rx.pipe = priv->in_pipe[MT7921_USB_IN_PKT_RX];
    priv->data_rx.buffer_size = MT7921_DATA_RX_BUF_SIZE;
    priv->data_rx.buffer = alloc_frames_bytes(priv->data_rx.buffer_size);
    priv->data_rx.enabled = true;
    priv->data_rx.is_cmd = false;
    priv->data_rx.name = "mt7921-rx-data";
    if (!priv->data_rx.buffer) {
        return -ENOMEM;
    }

    priv->cmd_rx.priv = priv;
    priv->cmd_rx.pipe = priv->in_pipe[MT7921_USB_IN_CMD_RESP];
    priv->cmd_rx.buffer_size = MT7921_CMD_RX_BUF_SIZE;
    priv->cmd_rx.buffer = alloc_frames_bytes(priv->cmd_rx.buffer_size);
    priv->cmd_rx.enabled = true;
    priv->cmd_rx.is_cmd = true;
    priv->cmd_rx.name = "mt7921-rx-cmd";
    if (!priv->cmd_rx.buffer) {
        free_frames_bytes(priv->data_rx.buffer, priv->data_rx.buffer_size);
        priv->data_rx.buffer = NULL;
        return -ENOMEM;
    }

    __atomic_store_n(&priv->rx_workers, 2, __ATOMIC_RELEASE);
    priv->data_rx.task =
        task_create(priv->data_rx.name, mt7921_rx_worker,
                    (uint64_t)&priv->data_rx, KTHREAD_PRIORITY);
    priv->cmd_rx.task = task_create(priv->cmd_rx.name, mt7921_rx_worker,
                                    (uint64_t)&priv->cmd_rx, KTHREAD_PRIORITY);
    if (!priv->data_rx.task || !priv->cmd_rx.task) {
        priv->running = false;
        priv->data_rx.enabled = false;
        priv->cmd_rx.enabled = false;
        wait_deadline = nano_time() + 500000000ULL;
        while (__atomic_load_n(&priv->rx_workers, __ATOMIC_ACQUIRE) > 0 &&
               nano_time() < wait_deadline) {
            task_block(current_task, TASK_BLOCKING, 1000000, "mt7921_rx_wait");
        }
        if (priv->data_rx.buffer) {
            free_frames_bytes(priv->data_rx.buffer, priv->data_rx.buffer_size);
            priv->data_rx.buffer = NULL;
        }
        if (priv->cmd_rx.buffer) {
            free_frames_bytes(priv->cmd_rx.buffer, priv->cmd_rx.buffer_size);
            priv->cmd_rx.buffer = NULL;
        }
        return -ENOMEM;
    }

    return 0;
}

void mt7921_usb_stop_rx(mt7921_priv_t *priv) {
    uint64_t wait_deadline;

    if (!priv) {
        return;
    }

    priv->running = false;
    priv->data_rx.enabled = false;
    priv->cmd_rx.enabled = false;

    wait_deadline = nano_time() + 1000000000ULL;
    while (__atomic_load_n(&priv->rx_workers, __ATOMIC_ACQUIRE) > 0 &&
           nano_time() < wait_deadline) {
        task_block(current_task, TASK_BLOCKING, 1000000, "mt7921_rx_stop");
    }

    if (priv->data_rx.buffer) {
        free_frames_bytes(priv->data_rx.buffer, priv->data_rx.buffer_size);
        priv->data_rx.buffer = NULL;
    }
    if (priv->cmd_rx.buffer) {
        free_frames_bytes(priv->cmd_rx.buffer, priv->cmd_rx.buffer_size);
        priv->cmd_rx.buffer = NULL;
    }

    priv->data_rx.task = NULL;
    priv->cmd_rx.task = NULL;
}

int mt7921_usb_send_raw(mt7921_priv_t *priv, enum mt7921_usb_out_ep ep,
                        const void *payload, size_t payload_len) {
    uint32_t hdr;
    size_t tx_len = payload_len + 4;
    size_t pad = ((tx_len + 3U) & ~3U) + 4U - tx_len;
    uint8_t *buf;
    int ret;

    if (ep >= MT7921_USB_OUT_MAX || !priv->out_pipe[ep]) {
        return -ENODEV;
    }

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

    ret = usb_send_pipe(priv->out_pipe[ep], USB_DIR_OUT, NULL, buf,
                        (int)(tx_len + pad), MT7921_USB_TX_TIMEOUT_NS);
    free(buf);

    return ret ? -EIO : 0;
}

int mt7921_usb_wait_resp(mt7921_priv_t *priv, uint8_t seq, uint64_t timeout_ms,
                         uint8_t **resp_data, size_t *resp_len) {
    uint64_t deadline = nano_time() + timeout_ms * 1000000ULL;

    while (nano_time() < deadline) {
        if (mt7921_resp_pop_by_seq(priv, seq, resp_data, resp_len)) {
            return 0;
        }

        task_block(current_task, TASK_BLOCKING, 1000000, "mt7921_mcu_wait");
    }

    return -ETIMEDOUT;
}
