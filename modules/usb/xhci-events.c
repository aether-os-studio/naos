#include "xhci-hcd.h"
#include <libs/aether/irq.h>

spinlock_t xhci_event_handle_lock = {0};

// 事件处理函数
void xhci_handle_events(xhci_hcd_t *xhci) {
    spin_lock(&xhci_event_handle_lock);

    xhci_ring_t *event_ring = xhci->event_ring;
    int events_processed = 0;

    while (events_processed < 256) { // 避免无限循环
        xhci_trb_t *trb = &event_ring->trbs[event_ring->dequeue_index];

        // 检查cycle bit
        uint8_t cycle = (trb->control & TRB_FLAG_CYCLE) ? 1 : 0;
        if (cycle != event_ring->cycle_state) {
            break; // 没有更多事件
        }

        uint32_t trb_type = (trb->control >> 10) & 0x3F;

        switch (trb_type) {
        case TRB_TYPE_TRANSFER:
            xhci_complete_transfer(xhci, trb);
            break;

        case TRB_TYPE_CMD_COMPLETE:
            xhci_complete_command(xhci, trb);
            break;

        case TRB_TYPE_PORT_STATUS: {
            uint32_t port_id = ((trb->parameter >> 24) & 0xFF) - 1;
            printk("XHCI: Port status change on port %d\n", port_id);
            // xhci_handle_port_status(xhci, port_id);
        } break;

        default:
            printk("XHCI: Unknown event type %d\n", trb_type);
            break;
        }

        // 移动到下一个TRB
        event_ring->dequeue_index++;
        if (event_ring->dequeue_index >= event_ring->size) {
            event_ring->dequeue_index = 0;
            event_ring->cycle_state = !event_ring->cycle_state;
        }

        events_processed++;

        // 更新ERDP (Event Ring Dequeue Pointer)
        uint64_t erdp = event_ring->phys_addr +
                        (event_ring->dequeue_index * sizeof(xhci_trb_t));
        xhci_writeq(&xhci->intr_regs[0].erdp, erdp | (1 << 3)); // Set EHB
    }

    spin_unlock(&xhci_event_handle_lock);
}

void xhci_interrupt_handler(uint64_t irq_num, void *data, struct pt_regs *r) {
    xhci_hcd_t *hcd = data;
    xhci_handle_events(hcd);
}

void xhci_event_handler(xhci_hcd_t *xhci) {
    arch_enable_interrupt();
    while (xhci->event_thread.running) {
        xhci_handle_events(xhci);
        arch_pause();
    }
    arch_disable_interrupt();

    task_exit(0);
}

// 启动事件处理线程
int xhci_start_event_handler(xhci_hcd_t *xhci) {
    xhci->event_thread.running = true;
    xhci->event_thread.xhci = xhci;

    // #if defined(__x86_64__)
    //     struct msi_desc_t desc;
    //     memset(&desc, 0, sizeof(struct msi_desc_t));
    //     desc.irq_num = irq_allocate_irqnum();
    //     desc.processor = lapic_id();
    //     desc.edge_trigger = 0;
    //     desc.assert = 1;
    //     desc.msi_index = 0;
    //     desc.pci_dev = xhci->pci_dev;
    //     desc.pci.msi_attribute.can_mask = false;
    //     desc.pci.msi_attribute.is_64 = true;
    //     desc.pci.msi_attribute.is_msix = true;
    //     int ret = pci_enable_msi(&desc);
    //     if (ret < 0) {
    //         printk("Failed to enable MSI/MSI-X\n");
    //         return -1;
    //     }

    //     irq_regist_irq(desc.irq_num, xhci_interrupt_handler, desc.irq_num,
    //     xhci,
    //                    get_apic_controller(), "XHCI", IRQ_FLAGS_MSIX);
    // #endif

    task_create("xhci_event_handler", (void (*)(uint64_t))xhci_event_handler,
                (uint64_t)xhci, KTHREAD_PRIORITY);

    return 0;
}

// 停止事件处理线程
void xhci_stop_event_handler(xhci_hcd_t *xhci) {
    if (xhci->event_thread.running) {
        xhci->event_thread.running = false;
    }
}
