#include <arch/riscv64/drivers/fw_cfg.h>
#include <drivers/fdt/fdt.h>
#include <mm/mm.h>

/* 全局fw_cfg设备 */
struct fw_cfg_device fw_cfg_dev = {0};

/* MMIO寄存器偏移 */
#define FW_CFG_MMIO_SELECTOR 0x08
#define FW_CFG_MMIO_DATA 0x00
#define FW_CFG_MMIO_DMA 0x10

/* Signature */
#define FW_CFG_SIGNATURE_QEMU 0x554d4551 /* "QEMU" */

static inline uint16_t bswap16(uint16_t x) { return (x >> 8) | (x << 8); }

static inline uint32_t bswap32(uint32_t x) {
    return ((x >> 24) & 0xff) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) |
           ((x << 24) & 0xff000000);
}

static inline uint64_t bswap64(uint64_t x) {
    return ((uint64_t)bswap32(x) << 32) | bswap32(x >> 32);
}

static inline uint8_t mmio_read8(volatile void *addr) {
    return *(volatile uint8_t *)addr;
}

static inline void mmio_write8(volatile void *addr, uint8_t val) {
    *(volatile uint8_t *)addr = val;
}

static inline uint16_t mmio_read16(volatile void *addr) {
    return bswap16(*(volatile uint16_t *)addr);
}

static inline void mmio_write16(volatile void *addr, uint16_t val) {
    *(volatile uint16_t *)addr = bswap16(val);
}

static inline uint64_t mmio_read64(volatile void *addr) {
    return bswap64(*(volatile uint64_t *)addr);
}

static inline void mmio_write64(volatile void *addr, uint64_t val) {
    *(volatile uint64_t *)addr = bswap64(val);
}

void fw_cfg_select(struct fw_cfg_device *dev, uint16_t key) {
    if (dev->type == FW_CFG_TYPE_MMIO) {
        mmio_write16(dev->selector, key);
    }
}

void fw_cfg_read(struct fw_cfg_device *dev, void *buf, uint32_t len) {
    uint8_t *p = (uint8_t *)buf;

    if (dev->type == FW_CFG_TYPE_MMIO) {
        for (uint32_t i = 0; i < len; i++) {
            p[i] = mmio_read8(dev->data);
        }
    }
}

void fw_cfg_read_entry(struct fw_cfg_device *dev, uint16_t key, void *buf,
                       uint32_t len) {
    fw_cfg_select(dev, key);
    fw_cfg_read(dev, buf, len);
}

static int fw_cfg_dma_wait(struct fw_cfg_device *dev,
                           struct fw_cfg_dma_access *dma) {
    /* 轮询等待DMA完成 */
    uint32_t timeout = 1000000;
    while (timeout--) {
        uint32_t control = bswap32(dma->control);
        if ((control & ~FW_CFG_DMA_CTL_ERROR) == 0) {
            if (control & FW_CFG_DMA_CTL_ERROR) {
                return -1;
            }
            return 0;
        }
    }
    return -1; /* 超时 */
}

int fw_cfg_dma_read(struct fw_cfg_device *dev, uint16_t key, void *buf,
                    uint32_t len) {
    if (!dev->dma_enabled) {
        /* 回退到传统方式 */
        fw_cfg_read_entry(dev, key, buf, len);
        return 0;
    }

    /* 分配DMA描述符 */
    struct fw_cfg_dma_access dma __attribute__((aligned(16)));

    dma.control =
        bswap32(FW_CFG_DMA_CTL_SELECT | FW_CFG_DMA_CTL_READ | (key << 16));
    dma.length = bswap32(len);
    dma.address =
        bswap64(translate_address(get_current_page_dir(false), (uint64_t)buf));

    /* 启动DMA */
    uint64_t dma_phys =
        translate_address(get_current_page_dir(false), (uint64_t)&dma);
    if (dev->type == FW_CFG_TYPE_MMIO) {
        mmio_write64(dev->dma_addr, dma_phys);
    } else {
    }

    return fw_cfg_dma_wait(dev, &dma);
}

int fw_cfg_dma_write(struct fw_cfg_device *dev, uint16_t key, void *buf,
                     uint32_t len) {
    if (!dev->dma_enabled) {
        return -1;
    }

    struct fw_cfg_dma_access dma __attribute__((aligned(16)));

    dma.control =
        bswap32(FW_CFG_DMA_CTL_SELECT | FW_CFG_DMA_CTL_WRITE | (key << 16));
    dma.length = bswap32(len);
    dma.address =
        bswap64(translate_address(get_current_page_dir(false), (uint64_t)buf));

    uint64_t dma_phys =
        translate_address(get_current_page_dir(false), (uint64_t)&dma);
    if (dev->type == FW_CFG_TYPE_MMIO) {
        mmio_write64(dev->dma_addr, dma_phys);
    } else {
    }

    return fw_cfg_dma_wait(dev, &dma);
}

/**
 * 查找文件
 */
int fw_cfg_find_file(struct fw_cfg_device *dev, const char *name,
                     uint16_t *select, uint32_t *size) {
    uint32_t count;

    /* 读取文件数量 */
    fw_cfg_read_entry(dev, FW_CFG_FILE_DIR, &count, sizeof(count));
    count = bswap32(count);

    /* 遍历文件 */
    for (uint32_t i = 0; i < count; i++) {
        struct fw_cfg_file file;
        fw_cfg_read(dev, &file, sizeof(file));

        file.size = bswap32(file.size);
        file.select = bswap16(file.select);

        if (strcmp(file.name, name) == 0) {
            if (select)
                *select = file.select;
            if (size)
                *size = file.size;
            return 0;
        }
    }

    return -1; /* 未找到 */
}

/**
 * 从设备树检测MMIO fw_cfg
 */
static int fw_cfg_detect_dt(struct fw_cfg_device *dev) {
    int node_offset;
    const void *prop;
    int len;

    node_offset = -1;
    uint32_t *p = (uint32_t *)g_fdt_ctx.dt_struct;
    int depth = 0;

    while (1) {
        uint32_t tag = fdt32_to_cpu(*p++);

        switch (tag) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)p;
            int node_off = (uint8_t *)p - (uint8_t *)g_fdt_ctx.dt_struct - 4;

            // 检查 compatible 属性
            int len;
            const char *compatible =
                fdt_get_property(node_off, "compatible", &len);
            if (compatible && strstr(compatible, "qemu,fw-cfg-mmio")) {
                node_offset = node_off;
                goto found_node;
            }

            depth++;
            p = (uint32_t *)ALIGN_UP((uintptr_t)p + strlen(name) + 1, 4);
            break;
        }

        case FDT_END_NODE:
            depth--;
            break;

        case FDT_PROP: {
            struct fdt_property *prop = (struct fdt_property *)p;
            uint32_t len = fdt32_to_cpu(prop->len);
            p = (uint32_t *)ALIGN_UP(
                (uintptr_t)p + sizeof(struct fdt_property) + len, 4);
            break;
        }

        case FDT_END:
            return -1;

        default:
            break;
        }
    }

found_node:
    /* 读取寄存器基地址 */
    prop = fdt_get_property(node_offset, "reg", &len);
    if (!prop || len < 8) {
        return -1;
    }

    const uint64_t *reg = (const uint64_t *)prop;
    uint64_t base_addr = fdt64_to_cpu(reg[0]);
    uint64_t size = len >= 16 ? fdt64_to_cpu(reg[1]) : 0x1000;

    dev->mmio_base = (volatile void *)phys_to_virt(base_addr);
    map_page_range(
        get_current_page_dir(false), (uint64_t)dev->mmio_base, base_addr,
        (size + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1),
        PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE | PT_FLAG_DEVICE);
    dev->selector =
        (volatile uint16_t *)((uint8_t *)dev->mmio_base + FW_CFG_MMIO_SELECTOR);
    dev->data =
        (volatile uint8_t *)((uint8_t *)dev->mmio_base + FW_CFG_MMIO_DATA);
    dev->dma_addr =
        (volatile uint64_t *)((uint8_t *)dev->mmio_base + FW_CFG_MMIO_DMA);
    dev->type = FW_CFG_TYPE_MMIO;

    return 0;
}

/**
 * 初始化fw_cfg设备
 */
int fw_cfg_init() {
#ifdef OPENSBI
    struct fw_cfg_device *dev = &fw_cfg_dev;

    if (dev->initialized) {
        return 0;
    }

    if (fw_cfg_detect_dt(dev) != 0) {
        return -1;
    }

    uint32_t sig;
    fw_cfg_read_entry(dev, FW_CFG_SIGNATURE, &sig, sizeof(sig));
    sig = bswap32(sig);

    dev->signature = sig;

    uint32_t id;
    fw_cfg_read_entry(dev, FW_CFG_ID, &id, sizeof(id));
    dev->revision = bswap32(id);

    dev->dma_enabled = (id & 0x02) != 0;

    dev->initialized = true;
#endif

    return 0;
}
