#pragma once

#include <libs/klibc.h>

/* FW_CFG 选择器定义 */
#define FW_CFG_SIGNATURE 0x0000
#define FW_CFG_ID 0x0001
#define FW_CFG_FILE_DIR 0x0019
#define FW_CFG_KERNEL_SIZE 0x0008
#define FW_CFG_INITRD_SIZE 0x000b

/* FW_CFG DMA 控制位 */
#define FW_CFG_DMA_CTL_ERROR 0x01
#define FW_CFG_DMA_CTL_READ 0x02
#define FW_CFG_DMA_CTL_SKIP 0x04
#define FW_CFG_DMA_CTL_SELECT 0x08
#define FW_CFG_DMA_CTL_WRITE 0x10

/* FW_CFG 文件结构 */
struct fw_cfg_file {
    uint32_t size;
    uint16_t select;
    uint16_t reserved;
    char name[56];
} __attribute__((packed));

/* FW_CFG 文件目录 */
struct fw_cfg_files {
    uint32_t count;
    struct fw_cfg_file files[];
} __attribute__((packed));

/* FW_CFG DMA 描述符 */
struct fw_cfg_dma_access {
    uint32_t control;
    uint32_t length;
    uint64_t address;
} __attribute__((packed));

/* FW_CFG 设备类型 */
enum fw_cfg_type {
    FW_CFG_TYPE_MMIO,
};

/* FW_CFG 设备结构 */
struct fw_cfg_device {
    enum fw_cfg_type type;

    /* MMIO接口地址 */
    volatile void *mmio_base;
    volatile uint16_t *selector;
    volatile uint8_t *data;
    volatile uint64_t *dma_addr;

    /* IO Port接口 */
    uint16_t ioport_selector;
    uint16_t ioport_data;

    /* 设备信息 */
    uint32_t signature;
    uint32_t revision;
    bool dma_enabled;
    bool initialized;
};

/* FW_CFG 驱动接口 */
int fw_cfg_init();

/* 基础读写接口 */
void fw_cfg_select(struct fw_cfg_device *dev, uint16_t key);
void fw_cfg_read(struct fw_cfg_device *dev, void *buf, uint32_t len);
void fw_cfg_read_entry(struct fw_cfg_device *dev, uint16_t key, void *buf,
                       uint32_t len);

/* DMA接口 */
int fw_cfg_dma_read(struct fw_cfg_device *dev, uint16_t key, void *buf,
                    uint32_t len);
int fw_cfg_dma_write(struct fw_cfg_device *dev, uint16_t key, void *buf,
                     uint32_t len);

/* 文件接口 */
int fw_cfg_find_file(struct fw_cfg_device *dev, const char *name,
                     uint16_t *select, uint32_t *size);
