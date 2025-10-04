// msc.h
#ifndef USB_MSC_H
#define USB_MSC_H

#include <libs/aether/usb.h>
#include <libs/aether/block.h>

// USB Mass Storage Class 定义
#define USB_CLASS_MASS_STORAGE 0x08

// Mass Storage Subclass
#define MSC_SUBCLASS_RBC 0x01
#define MSC_SUBCLASS_ATAPI 0x02
#define MSC_SUBCLASS_QIC157 0x03
#define MSC_SUBCLASS_UFI 0x04
#define MSC_SUBCLASS_SFF8070I 0x05
#define MSC_SUBCLASS_SCSI 0x06

// Mass Storage Protocol
#define MSC_PROTOCOL_CBI 0x00
#define MSC_PROTOCOL_CB 0x01
#define MSC_PROTOCOL_BBB 0x50 // Bulk-Only Transport

// Class-Specific Requests
#define MSC_REQ_BULK_ONLY_RESET 0xFF
#define MSC_REQ_GET_MAX_LUN 0xFE

// Command Block Wrapper (CBW) 定义
#define CBW_SIGNATURE 0x43425355 // "USBC"
#define CBW_FLAGS_DATA_OUT 0x00
#define CBW_FLAGS_DATA_IN 0x80

// Command Status Wrapper (CSW) 定义
#define CSW_SIGNATURE 0x53425355 // "USBS"
#define CSW_STATUS_GOOD 0x00
#define CSW_STATUS_FAILED 0x01
#define CSW_STATUS_PHASE_ERROR 0x02

// SCSI 命令
#define SCSI_TEST_UNIT_READY 0x00
#define SCSI_REQUEST_SENSE 0x03
#define SCSI_INQUIRY 0x12
#define SCSI_MODE_SENSE_6 0x1A
#define SCSI_START_STOP_UNIT 0x1B
#define SCSI_READ_FORMAT_CAPACITY 0x23
#define SCSI_READ_CAPACITY_10 0x25
#define SCSI_READ_10 0x28
#define SCSI_WRITE_10 0x2A
#define SCSI_VERIFY_10 0x2F
#define SCSI_MODE_SENSE_10 0x5A

// Command Block Wrapper
typedef struct {
    uint32_t signature;   // CBW_SIGNATURE
    uint32_t tag;         // Command Block Tag
    uint32_t data_length; // Expected data transfer length
    uint8_t flags;        // Direction flag
    uint8_t lun;          // Logical Unit Number
    uint8_t cb_length;    // Command Block length (1-16)
    uint8_t cb[16];       // Command Block
} __attribute__((packed)) usb_msc_cbw_t;

// Command Status Wrapper
typedef struct {
    uint32_t signature;    // CSW_SIGNATURE
    uint32_t tag;          // Command Block Tag (from CBW)
    uint32_t data_residue; // Difference between expected and actual data
    uint8_t status;        // Status code
} __attribute__((packed)) usb_msc_csw_t;

// SCSI Inquiry 数据
typedef struct {
    uint8_t peripheral;        // Peripheral Device Type
    uint8_t removable;         // Removable Media Bit
    uint8_t version;           // SCSI Version
    uint8_t response_format;   // Response Data Format
    uint8_t additional_length; // Additional Length
    uint8_t reserved[3];
    uint8_t vendor_id[8];   // Vendor Identification
    uint8_t product_id[16]; // Product Identification
    uint8_t revision[4];    // Product Revision Level
} __attribute__((packed)) scsi_inquiry_data_t;

// SCSI Read Capacity 数据
typedef struct {
    uint32_t last_lba;   // Last Logical Block Address
    uint32_t block_size; // Block Size in bytes
} __attribute__((packed)) scsi_read_capacity_data_t;

// SCSI Sense 数据
typedef struct {
    uint8_t response_code;
    uint8_t obsolete;
    uint8_t sense_key;
    uint8_t information[4];
    uint8_t additional_length;
    uint8_t command_specific[4];
    uint8_t asc;  // Additional Sense Code
    uint8_t ascq; // Additional Sense Code Qualifier
    uint8_t fruc;
    uint8_t sense_key_specific[3];
} __attribute__((packed)) scsi_sense_data_t;

// MSC 设备结构
typedef struct usb_msc_device {
    usb_device_t *usb_device;

    uint8_t interface_number;
    uint8_t bulk_in_ep;
    uint8_t bulk_out_ep;
    uint16_t max_packet_size;

    uint8_t max_lun; // Maximum Logical Unit Number
    uint32_t tag;    // Current command tag

    // 设备信息
    uint32_t block_count; // Total number of blocks
    uint32_t block_size;  // Size of each block in bytes
    uint64_t capacity;    // Total capacity in bytes

    char vendor[9];
    char product[17];
    char revision[5];

    bool ready;
    bool write_protected;

    struct usb_msc_device *next;
} usb_msc_device_t;

// MSC 驱动 API
int usb_msc_init(void);
int usb_msc_probe(usb_device_t *device);
void usb_msc_remove(usb_msc_device_t *msc);

// SCSI 命令
int msc_inquiry(usb_msc_device_t *msc);
int msc_test_unit_ready(usb_msc_device_t *msc);
int msc_request_sense(usb_msc_device_t *msc, scsi_sense_data_t *sense);
int msc_read_capacity(usb_msc_device_t *msc);

// 读写操作
int msc_read_blocks(usb_msc_device_t *msc, uint32_t lba, uint32_t count,
                    void *buffer);
int msc_write_blocks(usb_msc_device_t *msc, uint32_t lba, uint32_t count,
                     const void *buffer);

// 辅助函数
int msc_bulk_only_reset(usb_msc_device_t *msc);
int msc_get_max_lun(usb_msc_device_t *msc, uint8_t *max_lun);

// 内部函数
int msc_send_cbw(usb_msc_device_t *msc, usb_msc_cbw_t *cbw);
int msc_receive_csw(usb_msc_device_t *msc, usb_msc_csw_t *csw);
int msc_transfer(usb_msc_device_t *msc, uint8_t *cb, uint8_t cb_len, void *data,
                 uint32_t data_len, bool data_in);

// 字节序转换
static inline uint32_t be32_to_cpu(uint32_t val) {
    return __builtin_bswap32(val);
}

static inline uint32_t cpu_to_be32(uint32_t val) {
    return __builtin_bswap32(val);
}

static inline uint16_t be16_to_cpu(uint16_t val) {
    return __builtin_bswap16(val);
}

#endif // USB_MSC_H
