#include "mmio.h"

extern virtio_driver_op_t virtio_mmio_ops;

static virtio_driver_t *virtio_mmio_init(void *data) {
    virtio_mmio_device_t *mmio_dev = (virtio_mmio_device_t *)data;

    if (!mmio_dev || !mmio_dev->base) {
        return NULL;
    }

    /* 验证 Magic Number */
    uint32_t magic = virtio_mmio_read32(mmio_dev, VIRTIO_MMIO_MAGIC_VALUE);
    if (magic != VIRTIO_MMIO_MAGIC) {
        printk("VirtIO MMIO: Invalid magic value 0x%x\n", magic);
        return NULL;
    }

    /* 读取版本和设备ID */
    mmio_dev->version = virtio_mmio_read32(mmio_dev, VIRTIO_MMIO_VERSION);
    mmio_dev->device_id = virtio_mmio_read32(mmio_dev, VIRTIO_MMIO_DEVICE_ID);

    if (mmio_dev->version < 1 || mmio_dev->version > 2) {
        printk("VirtIO MMIO: Unsupported version %d\n", mmio_dev->version);
        return NULL;
    }

    if (mmio_dev->version == 1) {
        virtio_mmio_write32(mmio_dev, VIRTIO_MMIO_LEGACY_GUEST_PAGE_SIZE, 4096);
    }

    /* 重置设备 */
    virtio_mmio_write32(mmio_dev, VIRTIO_MMIO_STATUS, 0);

    virtio_driver_t *driver = malloc(sizeof(virtio_driver_t));
    driver->data = mmio_dev;
    driver->op = &virtio_mmio_ops;

    return driver; // 返回驱动句柄
}

static virtio_device_type_t virtio_mmio_get_device_type(void *data) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;
    return (virtio_device_type_t)dev->device_id;
}

static uint64_t virtio_mmio_get_features(void *data) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;
    uint64_t features = 0;

    /* 读取低32位特性 */
    virtio_mmio_write32(dev, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
    features = virtio_mmio_read32(dev, VIRTIO_MMIO_DEVICE_FEATURES);

    /* 读取高32位特性 (VirtIO 1.0+) */
    if (dev->version >= 2) {
        virtio_mmio_write32(dev, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 1);
        features |=
            ((uint64_t)virtio_mmio_read32(dev, VIRTIO_MMIO_DEVICE_FEATURES))
            << 32;
    }

    return features;
}

static void virtio_mmio_set_features(void *data, uint64_t features) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;

    /* 写入低32位特性 */
    virtio_mmio_write32(dev, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
    virtio_mmio_write32(dev, VIRTIO_MMIO_DRIVER_FEATURES, (uint32_t)features);

    /* 写入高32位特性 (VirtIO 1.0+) */
    if (dev->version >= 2) {
        virtio_mmio_write32(dev, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1);
        virtio_mmio_write32(dev, VIRTIO_MMIO_DRIVER_FEATURES,
                            (uint32_t)(features >> 32));
    }
}

static uint32_t virtio_mmio_get_max_queue_size(void *data, uint16_t queue) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;

    virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_SEL, queue);
    return virtio_mmio_read32(dev, VIRTIO_MMIO_QUEUE_NUM_MAX);
}

static void virtio_mmio_notify(void *data, uint16_t queue) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;
    virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_NOTIFY, queue);
}

static uint32_t virtio_mmio_get_status(void *data) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;
    return virtio_mmio_read32(dev, VIRTIO_MMIO_STATUS);
}

static void virtio_mmio_set_status(void *data, uint32_t status) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;
    virtio_mmio_write32(dev, VIRTIO_MMIO_STATUS, status);
}

static void virtio_mmio_queue_set(void *data, uint16_t queue, uint32_t size,
                                  uint64_t descriptors_paddr,
                                  uint64_t driver_area_paddr,
                                  uint64_t device_area_paddr) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;

    /* 选择队列 */
    virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_SEL, queue);

    /* 设置队列大小 */
    virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_NUM, size);

    if (dev->version == 1) {
        /* ===== Legacy VirtIO (v0.9.5) ===== */

        /* 设置对齐值（通常是页大小 4096） */
        virtio_mmio_write32(dev, VIRTIO_MMIO_LEGACY_QUEUE_ALIGN, 4096);

        /* 计算页帧号（PFN = 物理地址 / 页大小） */
        uint32_t pfn = descriptors_paddr >> 12; // 除以 4096

        /* 写入队列页帧号 - 这是关键！ */
        virtio_mmio_write32(dev, VIRTIO_MMIO_LEGACY_QUEUE_PFN, pfn);

        /* Legacy 模式：
         * - 不使用 QUEUE_DESC_LOW/HIGH
         * - 不使用 QUEUE_DRIVER_LOW/HIGH
         * - 不使用 QUEUE_DEVICE_LOW/HIGH
         * - 不使用 QUEUE_READY
         * - 只需要一个连续内存块，通过 PFN 指定起始地址
         * - 设备会根据 queue size 自动计算 avail 和 used 的偏移
         */

    } else {
        /* ===== VirtIO 1.0+ (Modern) ===== */

        /* Descriptor Table */
        virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_DESC_LOW,
                            (uint32_t)descriptors_paddr);
        virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_DESC_HIGH,
                            (uint32_t)(descriptors_paddr >> 32));

        /* Available Ring (Driver Area) */
        virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_DRIVER_LOW,
                            (uint32_t)driver_area_paddr);
        virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_DRIVER_HIGH,
                            (uint32_t)(driver_area_paddr >> 32));

        /* Used Ring (Device Area) */
        virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_DEVICE_LOW,
                            (uint32_t)device_area_paddr);
        virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_DEVICE_HIGH,
                            (uint32_t)(device_area_paddr >> 32));

        /* 启用队列 */
        virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_READY, 1);
    }
}

static bool virtio_mmio_queue_used(void *data, uint16_t queue) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;

    virtio_mmio_write32(dev, VIRTIO_MMIO_QUEUE_SEL, queue);

    if (dev->version == 1) {
        /* Legacy 版本通过检查 PFN 是否非零 */
        return virtio_mmio_read32(dev, VIRTIO_MMIO_QUEUE_DESC_LOW) != 0;
    } else {
        /* VirtIO 1.0+ 通过 QUEUE_READY */
        return virtio_mmio_read32(dev, VIRTIO_MMIO_QUEUE_READY) != 0;
    }
}

static bool virtio_mmio_requires_legacy_layout(void *data) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;
    return dev->version == 1;
}

static uint32_t virtio_mmio_read_config_space(void *data, uint32_t offset) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;
    return virtio_mmio_read32(dev, VIRTIO_MMIO_CONFIG + offset);
}

static void virtio_mmio_write_config_space(void *data, uint32_t offset,
                                           uint32_t value) {
    virtio_mmio_device_t *dev = (virtio_mmio_device_t *)data;
    virtio_mmio_write32(dev, VIRTIO_MMIO_CONFIG + offset, value);
}

virtio_driver_op_t virtio_mmio_ops = {
    .init = virtio_mmio_init,
    .get_device_type = virtio_mmio_get_device_type,
    .get_features = virtio_mmio_get_features,
    .set_features = virtio_mmio_set_features,
    .get_max_queue_size = virtio_mmio_get_max_queue_size,
    .notify = virtio_mmio_notify,
    .get_status = virtio_mmio_get_status,
    .set_status = virtio_mmio_set_status,
    .queue_set = virtio_mmio_queue_set,
    .queue_used = virtio_mmio_queue_used,
    .requires_legacy_layout = virtio_mmio_requires_legacy_layout,
    .read_config_space = virtio_mmio_read_config_space,
    .write_config_space = virtio_mmio_write_config_space,
};
