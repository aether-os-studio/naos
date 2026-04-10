#include <drivers/bus/pci_msi.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <drivers/logger.h>

struct msi_msg_t *msi_arch_get_msg(struct msi_desc_t *msi_desc) {
#if defined(__x86_64__)
    msi_desc->msg.address_hi = msi_desc->processor & 0xFFFFFF00;
    msi_desc->msg.address_lo =
        ia64_pci_get_arch_msi_message_address(msi_desc->processor);
    msi_desc->msg.data = ia64_pci_get_arch_msi_message_data(
        msi_desc->irq_num, msi_desc->processor, msi_desc->edge_trigger,
        msi_desc->assert);
    msi_desc->msg.vector_control = 0;
#endif
    return &(msi_desc->msg);
}

static inline struct pci_msi_cap_t
__msi_read_cap_list(struct msi_desc_t *msi_desc, uint32_t cap_off) {
    struct pci_msi_cap_t cap_list = {0};
    pci_device_t *ptr = msi_desc->pci_dev;
    uint32_t dw0;
    dw0 =
        ptr->op->read32(ptr->bus, ptr->slot, ptr->func, ptr->segment, cap_off);
    cap_list.cap_id = dw0 & 0xff;
    cap_list.next_off = (dw0 >> 8) & 0xff;
    cap_list.msg_ctrl = (dw0 >> 16) & 0xffff;

    cap_list.msg_addr_lo = ptr->op->read32(ptr->bus, ptr->slot, ptr->func,
                                           ptr->segment, cap_off + 0x4);
    uint16_t msg_data_off = 0xc;
    if (cap_list.msg_ctrl & (1 << 7)) // 64位
    {
        cap_list.msg_addr_hi = ptr->op->read32(ptr->bus, ptr->slot, ptr->func,
                                               ptr->segment, cap_off + 0x8);
    } else {
        cap_list.msg_addr_hi = 0;
        msg_data_off = 0x8;
    }

    cap_list.msg_data = ptr->op->read32(ptr->bus, ptr->slot, ptr->func,
                                        ptr->segment, cap_off + msg_data_off) &
                        0xffff;

    cap_list.mask = ptr->op->read32(ptr->bus, ptr->slot, ptr->func,
                                    ptr->segment, cap_off + 0x10);
    cap_list.pending = ptr->op->read32(ptr->bus, ptr->slot, ptr->func,
                                       ptr->segment, cap_off + 0x14);

    return cap_list;
}

static inline struct pci_msix_cap_t
__msi_read_msix_cap_list(struct msi_desc_t *msi_desc, uint32_t cap_off) {
    struct pci_msix_cap_t cap_list = {0};
    pci_device_t *ptr = msi_desc->pci_dev;
    uint32_t dw0;
    dw0 =
        ptr->op->read32(ptr->bus, ptr->slot, ptr->func, ptr->segment, cap_off);
    cap_list.cap_id = dw0 & 0xff;
    cap_list.next_off = (dw0 >> 8) & 0xff;
    cap_list.msg_ctrl = (dw0 >> 16) & 0xffff;

    cap_list.dword1 = ptr->op->read32(ptr->bus, ptr->slot, ptr->func,
                                      ptr->segment, cap_off + 0x4);
    cap_list.dword2 = ptr->op->read32(ptr->bus, ptr->slot, ptr->func,
                                      ptr->segment, cap_off + 0x8);
    return cap_list;
}

static inline int __msix_map_table(pci_device_t *pci_dev,
                                   struct pci_msix_cap_t *msix_cap) {
    pci_dev->msix_offset = msix_cap->dword1 & (~0x7);
    pci_dev->msix_table_size = (msix_cap->msg_ctrl & 0x7ff) + 1;
    pci_dev->msix_mmio_size =
        pci_dev->msix_table_size * 16 + pci_dev->msix_offset;

    uint32_t bir = msix_cap->dword1 & 0x7;
    if (bir > 5) {
        printk("MSI-X: Invalid bir %d\n", bir);
        return -EINVAL;
    }

    uint64_t bar_physical_address = pci_dev->bars[bir].address;

    if (bar_physical_address == 0) {
        return -ENOMEM;
    }

    pci_dev->msix_mmio_vaddr =
        (uint64_t)phys_to_virt((uint64_t)bar_physical_address);
    map_page_range(get_current_page_dir(false), pci_dev->msix_mmio_vaddr,
                   bar_physical_address, pci_dev->bars[bir].size,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);

    return 0;
}

static inline void __msix_set_entry(struct msi_desc_t *msi_desc) {
    uint64_t table_base =
        msi_desc->pci_dev->msix_mmio_vaddr + msi_desc->pci_dev->msix_offset;
    volatile uint32_t *entry_ptr =
        (volatile uint32_t *)(table_base + msi_desc->msi_index * 16);

    entry_ptr[0] = msi_desc->msg.address_lo;
    entry_ptr[1] = msi_desc->msg.address_hi;

    entry_ptr[2] = msi_desc->msg.data;
    entry_ptr[3] = msi_desc->msg.vector_control & ~1;
}

static inline void __msix_clear_entry(pci_device_t *pci_dev,
                                      uint16_t msi_index) {
    uint64_t table_base = pci_dev->msix_mmio_vaddr + pci_dev->msix_offset;
    volatile uint64_t *entry_ptr =
        (volatile uint64_t *)(table_base + msi_index * 16);

    // 清除MSI-X表项
    entry_ptr[0] = 0;
    entry_ptr[1] = 0;
}

int pci_enable_msi(struct msi_desc_t *msi_desc) {
    pci_device_t *ptr;
    uint32_t cap_ptr;
    uint16_t command;
    uint16_t message_control;

    if (!msi_desc || !msi_desc->pci_dev || !msi_desc->pci_dev->op)
        return -EINVAL;

    ptr = msi_desc->pci_dev;

    if (msi_desc->pci.msi_attribute.is_msix) {
        cap_ptr = pci_enumerate_capability_list(ptr, 0x11);
        if (cap_ptr == 0) {
            cap_ptr = pci_enumerate_capability_list(ptr, 0x05);
            if (cap_ptr == 0)
                return -ENOSYS;
            msi_desc->pci.msi_attribute.is_msix = 0;
        }
    } else {
        cap_ptr = pci_enumerate_capability_list(ptr, 0x05);
        if (cap_ptr == 0)
            return -ENOSYS;
        msi_desc->pci.msi_attribute.is_msix = 0;
    }

    msi_arch_get_msg(msi_desc);

    command = ptr->op->read16(ptr->bus, ptr->slot, ptr->func, ptr->segment,
                              PCI_CONF_COMMAND);
    command |= (1U << 10);
    ptr->op->write16(ptr->bus, ptr->slot, ptr->func, ptr->segment,
                     PCI_CONF_COMMAND, command);

    if (msi_desc->pci.msi_attribute.is_msix) {
        struct pci_msix_cap_t cap = __msi_read_msix_cap_list(msi_desc, cap_ptr);

        if (ptr->msix_mmio_vaddr == 0) {
            int ret = __msix_map_table(ptr, &cap);
            if (ret < 0)
                return ret;
        }

        if (msi_desc->msi_index >= ptr->msix_table_size)
            return -EINVAL;

        __msix_set_entry(msi_desc);

        message_control = ptr->op->read16(ptr->bus, ptr->slot, ptr->func,
                                          ptr->segment, cap_ptr + 0x2);
        message_control &= ~(1U << 14);
        message_control |= (1U << 15);
        ptr->op->write16(ptr->bus, ptr->slot, ptr->func, ptr->segment,
                         cap_ptr + 0x2, message_control);
        return 0;
    }

    message_control = ptr->op->read16(ptr->bus, ptr->slot, ptr->func,
                                      ptr->segment, cap_ptr + 0x2);
    ptr->op->write32(ptr->bus, ptr->slot, ptr->func, ptr->segment,
                     cap_ptr + 0x4, msi_desc->msg.address_lo);

    if (message_control & (1U << 7)) {
        ptr->op->write32(ptr->bus, ptr->slot, ptr->func, ptr->segment,
                         cap_ptr + 0x8, msi_desc->msg.address_hi);
        ptr->op->write16(ptr->bus, ptr->slot, ptr->func, ptr->segment,
                         cap_ptr + 0xC, (uint16_t)msi_desc->msg.data);
    } else {
        ptr->op->write16(ptr->bus, ptr->slot, ptr->func, ptr->segment,
                         cap_ptr + 0x8, (uint16_t)msi_desc->msg.data);
    }

    message_control |= 1U;
    message_control &= ~(7U << 4);
    ptr->op->write16(ptr->bus, ptr->slot, ptr->func, ptr->segment,
                     cap_ptr + 0x2, message_control);

    return 0;
}
