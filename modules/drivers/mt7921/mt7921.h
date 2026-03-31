#pragma once

#include "mt7921_fw.h"
#include "mt7921_regs.h"

#include <drivers/bus/usb.h>
#include <libs/klibc.h>
#include <libs/mutex.h>
#include <net/wifi.h>
#include <task/task.h>

#define MT7921_USB_RX_TIMEOUT_NS 100000000ULL
#define MT7921_USB_TX_TIMEOUT_NS 1000000000ULL

#define MT7921_RESP_QUEUE_DEPTH 32
#define MT7921_DATA_QUEUE_DEPTH 64
#define MT7921_CMD_RX_BUF_SIZE 2048
#define MT7921_DATA_RX_BUF_SIZE 4096

enum mt7921_usb_in_ep {
    MT7921_USB_IN_PKT_RX = 0,
    MT7921_USB_IN_CMD_RESP = 1,
    MT7921_USB_IN_MAX,
};

enum mt7921_usb_out_ep {
    MT7921_USB_OUT_INBAND_CMD = 0,
    MT7921_USB_OUT_AC_BE = 1,
    MT7921_USB_OUT_AC_BK = 2,
    MT7921_USB_OUT_AC_VI = 3,
    MT7921_USB_OUT_AC_VO = 4,
    MT7921_USB_OUT_HCCA = 5,
    MT7921_USB_OUT_MAX,
};

typedef struct mt7921_ep_pair {
    usb_endpoint_descriptor_t *desc;
    usb_super_speed_endpoint_descriptor_t *ss_desc;
} mt7921_ep_pair_t;

typedef struct mt7921_queue_entry {
    uint8_t *data;
    size_t len;
} mt7921_queue_entry_t;

struct mt7921_priv;
struct net_device;

typedef struct mt7921_rx_channel {
    struct mt7921_priv *priv;
    usb_pipe_t *pipe;
    uint8_t *buffer;
    size_t buffer_size;
    task_t *task;
    bool enabled;
    bool is_cmd;
    const char *name;
} mt7921_rx_channel_t;

typedef struct mt7921_priv {
    usb_device_t *usbdev;
    usb_device_interface_t *iface;

    mutex_t usb_ctrl_mtx;
    mutex_t mcu_mutex;

    mt7921_ep_pair_t in_ep[MT7921_USB_IN_MAX];
    mt7921_ep_pair_t out_ep[MT7921_USB_OUT_MAX];
    usb_pipe_t *in_pipe[MT7921_USB_IN_MAX];
    usb_pipe_t *out_pipe[MT7921_USB_OUT_MAX];

    mt7921_rx_channel_t data_rx;
    mt7921_rx_channel_t cmd_rx;
    volatile int rx_workers;
    bool running;

    spinlock_t resp_lock;
    mt7921_queue_entry_t resp_q[MT7921_RESP_QUEUE_DEPTH];
    size_t resp_q_count;

    spinlock_t data_lock;
    mt7921_queue_entry_t data_q[MT7921_DATA_QUEUE_DEPTH];
    size_t data_q_count;
    spinlock_t scan_lock;

    uint8_t mcu_seq;
    uint8_t scan_seq;
    uint8_t macaddr[6];
    uint8_t antenna_mask;
    bool has_2ghz;
    bool has_5ghz;
    bool has_6ghz;
    bool removed;
    bool warned_rx_drop;
    bool warned_tx_stub;
    wifi_device_t *wifi;
    struct net_device *rtnl_dev;
    wifi_bss_info_t scan_results[WIFI_MAX_SCAN_RESULTS];
    uint32_t scan_result_count;
    wifi_bss_info_t target_bss;
    bool have_target_bss;
} mt7921_priv_t;

void mt7921_delay_us(uint64_t us);
void mt7921_delay_ms(uint64_t ms);
bool mt7921_wait_reg_mask(mt7921_priv_t *priv, uint32_t addr, uint32_t mask,
                          uint32_t want, uint64_t timeout_ms,
                          uint64_t interval_us);

int mt7921_vendor_request(mt7921_priv_t *priv, uint8_t req, uint8_t req_type,
                          uint16_t value, uint16_t index, void *buf,
                          size_t len);
uint32_t mt7921_read_uhw_reg(mt7921_priv_t *priv, uint32_t addr);
void mt7921_write_uhw_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t val);
uint32_t mt7921_read_reg(mt7921_priv_t *priv, uint32_t addr);
void mt7921_write_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t val);

int mt7921_wfsys_reset(mt7921_priv_t *priv);
int mt7921_mcu_power_on(mt7921_priv_t *priv);
int mt7921_dma_init(mt7921_priv_t *priv, bool resume);

int mt7921_usb_init(mt7921_priv_t *priv, usb_device_interface_t *iface);
void mt7921_usb_cleanup(mt7921_priv_t *priv);
int mt7921_usb_start_rx(mt7921_priv_t *priv);
void mt7921_usb_stop_rx(mt7921_priv_t *priv);
int mt7921_usb_send_raw(mt7921_priv_t *priv, enum mt7921_usb_out_ep ep,
                        const void *payload, size_t payload_len);
int mt7921_usb_wait_resp(mt7921_priv_t *priv, uint8_t seq, uint64_t timeout_ms,
                         uint8_t **resp_data, size_t *resp_len);

int mt7921_mcu_send_msg(mt7921_priv_t *priv, uint32_t cmd, const void *req,
                        size_t req_len, bool wait_resp, void *resp,
                        size_t resp_len);
int mt7921_run_firmware(mt7921_priv_t *priv);
int mt7921_data_pop(mt7921_priv_t *priv, uint8_t **data, size_t *len);
void mt7921_handle_mcu_event(mt7921_priv_t *priv, const void *data, size_t len);

int mt7921_wifi_register(mt7921_priv_t *priv);
void mt7921_wifi_remove(mt7921_priv_t *priv);
