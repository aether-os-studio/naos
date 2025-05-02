#include <drivers/virtio/virtio.h>
#include <mm/mm.h>

pci_device_t *virtio_devices[MAX_VIRTIO_DEV_NUM];
pci_device_t *valid_virtio_devices[MAX_VIRTIO_DEV_NUM];
uint32_t virtio_dev_num = 0;
uint32_t valid_virtio_dev_num = 0;

void virtio_keyboard_init(uint64_t mmio_addr)
{
    // 1. 映射设备寄存器
    volatile uint32_t *regs = (uint32_t *)(mmio_addr);

    // 2. 重置设备
    regs[VIRTIO_PCI_STATUS] = VIRTIO_STATUS_RESET;

    // 3. 设置ACKNOWLEDGE状态
    regs[VIRTIO_PCI_STATUS] |= VIRTIO_STATUS_ACKNOWLEDGE;

    // 4. 协商特性 (假设不需要特殊功能)
    uint32_t host_features = regs[VIRTIO_PCI_HOST_FEATURES];
    regs[VIRTIO_PCI_GUEST_FEATURES] = host_features & 0x1; // 仅启用基本功能

    // 5. 初始化队列 (队列0为事件接收队列)
    regs[VIRTIO_PCI_QUEUE_SELECT] = 0; // 选择队列0
    uint16_t queue_size = regs[VIRTIO_PCI_QUEUE_SIZE];

    // 分配virtqueue内存
    uint64_t vq_paddr = alloc_frames(1);
    regs[VIRTIO_PCI_QUEUE_PFN] = (uint32_t)(vq_paddr >> 12);

    // 6. 完成初始化
    regs[VIRTIO_PCI_STATUS] |= VIRTIO_STATUS_DRIVER_OK;
}

void virtio_init()
{
#if defined(__x86_64__) || defined(__aarch64__)
    // get from pci & pcie bus
    pci_find_vid(virtio_devices, &virtio_dev_num, 0x1AF4);

    for (uint32_t i = 0; i < virtio_dev_num; i++)
    {
        valid_virtio_devices[valid_virtio_dev_num] = virtio_devices[i];
        valid_virtio_dev_num++;
        continue;
    }
#else
    // get from fdt
#endif

    for (uint32_t i = 0; i < valid_virtio_dev_num; i++)
    {
        pci_device_t *dev = valid_virtio_devices[i];
        if (dev->device_id == 0x1052)
        {
            uint64_t phys = dev->bars[4].address;
            uint64_t virt = phys_to_virt(phys);
            uint64_t len = dev->bars[4].size;
            map_page_range(get_current_page_dir(false), virt, phys, len, PT_FLAG_R | PT_FLAG_W);
            virtio_keyboard_init(virt);
        }
    }
}
