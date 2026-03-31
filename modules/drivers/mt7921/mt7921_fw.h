#pragma once

#include <libs/klibc.h>

#define MT7921_FIRMWARE_WM "mediatek/WIFI_RAM_CODE_MT7961_1.bin"
#define MT7921_ROM_PATCH "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin"

#define MT7921_MCU_TIMEOUT_MS 3000U
#define MT7921_MCU_SCATTER_CHUNK 4096U

#define MT7921_MCU_CMD_FIELD_ID_MASK 0x000000ffU
#define MT7921_MCU_CMD_FIELD_EXT_ID_MASK 0x0000ff00U
#define MT7921_MCU_CMD_FIELD_QUERY (1U << 16)
#define MT7921_MCU_CMD_FIELD_CE (1U << 18)

#define MT7921_MCU_CMD(id) ((uint32_t)(id) & MT7921_MCU_CMD_FIELD_ID_MASK)
#define MT7921_MCU_CE_CMD(id) (MT7921_MCU_CMD_FIELD_CE | MT7921_MCU_CMD(id))

#define MT7921_MCU_CMD_TARGET_ADDRESS_LEN_REQ MT7921_MCU_CMD(0x01)
#define MT7921_MCU_CMD_FW_START_REQ MT7921_MCU_CMD(0x02)
#define MT7921_MCU_CMD_PATCH_START_REQ MT7921_MCU_CMD(0x05)
#define MT7921_MCU_CMD_PATCH_FINISH_REQ MT7921_MCU_CMD(0x07)
#define MT7921_MCU_CMD_PATCH_SEM_CONTROL MT7921_MCU_CMD(0x10)
#define MT7921_MCU_CMD_FW_SCATTER MT7921_MCU_CMD(0xee)

#define MT7921_MCU_CE_CMD_GET_NIC_CAPAB MT7921_MCU_CE_CMD(0x8a)
#define MT7921_MCU_CE_CMD_FWLOG_2_HOST MT7921_MCU_CE_CMD(0xc5)
#define MT7921_MCU_CE_CMD_START_HW_SCAN MT7921_MCU_CE_CMD(0x03)
#define MT7921_MCU_CE_CMD_CANCEL_HW_SCAN MT7921_MCU_CE_CMD(0x1b)
#define MT7921_MCU_CE_CMD_SET_BSS_CONNECTED MT7921_MCU_CE_CMD(0x16)
#define MT7921_MCU_CE_CMD_SET_BSS_ABORT MT7921_MCU_CE_CMD(0x17)
#define MT7921_MCU_CE_CMD_SET_EDCA_PARMS MT7921_MCU_CE_CMD(0x1d)

#define MT7921_MCU_UNI_CMD(id) MT7921_MCU_CMD(id)
#define MT7921_MCU_UNI_CMD_DEV_INFO_UPDATE MT7921_MCU_UNI_CMD(0x01)
#define MT7921_MCU_UNI_CMD_BSS_INFO_UPDATE MT7921_MCU_UNI_CMD(0x02)

#define MT7921_PATCH_SEM_RELEASE 0
#define MT7921_PATCH_SEM_GET 1
#define MT7921_PATCH_IS_DL 1
#define MT7921_PATCH_NOT_DL_SEM_SUCCESS 2
#define MT7921_PATCH_REL_SEM_SUCCESS 3

#define MT7921_FW_FEATURE_SET_ENCRYPT (1U << 0)
#define MT7921_FW_FEATURE_SET_KEY_IDX_MASK 0x06U
#define MT7921_FW_FEATURE_SET_KEY_IDX_SHIFT 1
#define MT7921_FW_FEATURE_ENCRY_MODE (1U << 4)
#define MT7921_FW_FEATURE_OVERRIDE_ADDR (1U << 5)
#define MT7921_FW_FEATURE_NON_DL (1U << 6)

#define MT7921_DL_MODE_ENCRYPT (1U << 0)
#define MT7921_DL_MODE_KEY_IDX_MASK 0x06U
#define MT7921_DL_MODE_KEY_IDX_SHIFT 1
#define MT7921_DL_MODE_RESET_SEC_IV (1U << 3)
#define MT7921_DL_MODE_NEED_RSP (1U << 31)
#define MT7921_DL_CONFIG_ENCRY_MODE_SEL (1U << 6)

#define MT7921_FW_START_OVERRIDE (1U << 0)
#define MT7921_PATCH_SEC_TYPE_MASK 0x0000ffffU
#define MT7921_PATCH_SEC_TYPE_INFO 0x2U
#define MT7921_PATCH_SEC_ENC_TYPE_MASK 0xff000000U
#define MT7921_PATCH_SEC_ENC_TYPE_SHIFT 24
#define MT7921_PATCH_SEC_ENC_TYPE_PLAIN 0x00U
#define MT7921_PATCH_SEC_ENC_TYPE_AES 0x01U
#define MT7921_PATCH_SEC_ENC_TYPE_SCRAMBLE 0x02U
#define MT7921_PATCH_SEC_ENC_AES_KEY_MASK 0x000000ffU

#define MT7921_PATCH_ADDRESS 0x200000U
#define MT7921_RAM_START_ADDRESS 0x900000U
#define MT7921_NIC_CAP_BUF_SIZE 1024U

#define MT7921_NIC_CAP_MAC_ADDR 7U
#define MT7921_NIC_CAP_PHY 8U
#define MT7921_NIC_CAP_6G 0x18U

#define MT7921_HW_PATH_2G_BIT (1U << 0)
#define MT7921_HW_PATH_5G_BIT (1U << 1)

#define MT7921_SCAN_FUNC_RANDOM_MAC (1U << 0)
#define MT7921_SCAN_FUNC_SPLIT_SCAN (1U << 5)

#define MT7921_MCU_EVENT_SCAN_DONE 0x0d
#define MT7921_MCU_EVENT_SCHED_SCAN_DONE 0x23

#define MT7921_SCAN_IE_LEN 600U
#define MT7921_SCAN_MAX_CHANNELS 32U
#define MT7921_SCAN_MAX_SSIDS 4U
#define MT7921_SDIO_TXD_SIZE 64U

#define MT7921_CONNECTION_INFRA_STA ((1U << 0) | (1U << 16))
#define MT7921_CONN_STATE_DISCONNECT 0U
#define MT7921_CONN_STATE_CONNECT 1U

#define MT7921_PHY_MODE_A (1U << 0)
#define MT7921_PHY_MODE_B (1U << 1)
#define MT7921_PHY_MODE_G (1U << 2)
#define MT7921_PHY_MODE_GN (1U << 3)
#define MT7921_PHY_MODE_AN (1U << 4)
#define MT7921_PHY_MODE_AC (1U << 5)
#define MT7921_PHY_MODE_AX_24G (1U << 6)
#define MT7921_PHY_MODE_AX_5G (1U << 7)

#define MT7921_UNI_BSS_INFO_BASIC 0U
#define MT7921_UNI_BSS_INFO_RLM 2U
#define MT7921_UNI_BSS_INFO_QBSS 15U
#define MT7921_DEV_INFO_ACTIVE 0U

#define MT7921_SDIO_HDR_TX_BYTES_MASK 0x0000ffffU
#define MT7921_SDIO_HDR_PKT_TYPE_SHIFT 16
#define MT7921_SDIO_HDR_PKT_TYPE_CMD 0U

struct mt7921_mcu_txd {
    uint32_t txd[8];
    uint16_t len;
    uint16_t pq_id;
    uint8_t cid;
    uint8_t pkt_type;
    uint8_t set_query;
    uint8_t seq;
    uint8_t uc_d2b0_rev;
    uint8_t ext_cid;
    uint8_t s2d_index;
    uint8_t ext_cid_ack;
    uint32_t rsv[5];
} __attribute__((packed));

struct mt7921_mcu_rxd {
    uint32_t rxd[6];
    uint16_t len;
    uint16_t pkt_type_id;
    uint8_t eid;
    uint8_t seq;
    uint8_t option;
    uint8_t rsv;
    uint8_t ext_eid;
    uint8_t rsv1[2];
    uint8_t s2d_index;
    uint8_t tlv[];
} __attribute__((packed));

struct mt7921_mcu_scan_ssid {
    uint32_t ssid_len;
    uint8_t ssid[32];
} __attribute__((packed));

struct mt7921_mcu_scan_channel {
    uint8_t band;
    uint8_t channel_num;
} __attribute__((packed));

struct mt7921_mcu_hw_scan_req {
    uint8_t seq_num;
    uint8_t bss_idx;
    uint8_t scan_type;
    uint8_t ssid_type;
    uint8_t ssids_num;
    uint8_t probe_req_num;
    uint8_t scan_func;
    uint8_t version;
    struct mt7921_mcu_scan_ssid ssids[MT7921_SCAN_MAX_SSIDS];
    uint16_t probe_delay_time;
    uint16_t channel_dwell_time;
    uint16_t timeout_value;
    uint8_t channel_type;
    uint8_t channels_num;
    struct mt7921_mcu_scan_channel channels[MT7921_SCAN_MAX_CHANNELS];
    uint16_t ies_len;
    uint8_t ies[MT7921_SCAN_IE_LEN];
    uint8_t ext_channels_num;
    uint8_t ext_ssids_num;
    uint16_t channel_min_dwell_time;
    struct mt7921_mcu_scan_channel ext_channels[MT7921_SCAN_MAX_CHANNELS];
    struct mt7921_mcu_scan_ssid ext_ssids[6];
    uint8_t bssid[6];
    uint8_t random_mac[6];
    uint8_t pad[63];
    uint8_t ssid_type_ext;
} __attribute__((packed));

struct mt7921_dev_info_req {
    struct {
        uint8_t omac_idx;
        uint8_t band_idx;
        uint16_t pad;
    } __attribute__((packed)) hdr;
    struct {
        uint16_t tag;
        uint16_t len;
        uint8_t active;
        uint8_t link_idx;
        uint8_t omac_addr[6];
    } __attribute__((packed)) tlv;
} __attribute__((packed));

struct mt7921_bss_basic_req {
    struct {
        uint8_t bss_idx;
        uint8_t pad[3];
    } __attribute__((packed)) hdr;
    struct {
        uint16_t tag;
        uint16_t len;
        uint8_t active;
        uint8_t omac_idx;
        uint8_t hw_bss_idx;
        uint8_t band_idx;
        uint32_t conn_type;
        uint8_t conn_state;
        uint8_t wmm_idx;
        uint8_t bssid[6];
        uint16_t bmc_tx_wlan_idx;
        uint16_t bcn_interval;
        uint8_t dtim_period;
        uint8_t phymode;
        uint16_t sta_idx;
        uint16_t nonht_basic_phy;
        uint8_t phymode_ext;
        uint8_t link_idx;
    } __attribute__((packed)) basic;
    struct {
        uint16_t tag;
        uint16_t len;
        uint8_t qos;
        uint8_t pad[3];
    } __attribute__((packed)) qos;
} __attribute__((packed));

struct mt7921_bss_rlm_req {
    struct {
        uint8_t bss_idx;
        uint8_t pad[3];
    } __attribute__((packed)) hdr;
    struct {
        uint16_t tag;
        uint16_t len;
        uint8_t control_channel;
        uint8_t center_chan;
        uint8_t center_chan2;
        uint8_t bw;
        uint8_t tx_streams;
        uint8_t rx_streams;
        uint8_t short_st;
        uint8_t ht_op_info;
        uint8_t sco;
        uint8_t band;
        uint8_t pad[2];
    } __attribute__((packed)) rlm;
} __attribute__((packed));

struct mt7921_mcu_tx_edca {
    uint16_t cw_min;
    uint16_t cw_max;
    uint16_t txop;
    uint16_t aifs;
    uint8_t guardtime;
    uint8_t acm;
} __attribute__((packed));

struct mt7921_mcu_tx_req {
    struct mt7921_mcu_tx_edca edca[4];
    uint8_t bss_idx;
    uint8_t qos;
    uint8_t wmm_idx;
    uint8_t pad;
} __attribute__((packed));

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

struct mt7921_mcu_patch_sem_req {
    uint32_t op;
} __attribute__((packed));

struct mt7921_mcu_patch_finish_req {
    uint8_t check_crc;
    uint8_t reserved[3];
} __attribute__((packed));

struct mt7921_mcu_init_download_req {
    uint32_t addr;
    uint32_t len;
    uint32_t mode;
} __attribute__((packed));

struct mt7921_mcu_fw_start_req {
    uint32_t option;
    uint32_t addr;
} __attribute__((packed));

struct mt7921_mcu_ce_fwlog_req {
    uint8_t ctrl_val;
    uint8_t pad[3];
} __attribute__((packed));

struct mt7921_cap_hdr {
    uint16_t n_element_le;
    uint8_t rsv[2];
} __attribute__((packed));

struct mt7921_cap_tlv {
    uint32_t type_le;
    uint32_t len_le;
} __attribute__((packed));

struct mt7921_phy_cap {
    uint8_t ht;
    uint8_t vht;
    uint8_t cap_5g;
    uint8_t max_bw;
    uint8_t nss;
    uint8_t dbdc;
    uint8_t tx_ldpc;
    uint8_t rx_ldpc;
    uint8_t tx_stbc;
    uint8_t rx_stbc;
    uint8_t hw_path;
    uint8_t he;
} __attribute__((packed));
