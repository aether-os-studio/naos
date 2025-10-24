#include "xhci-hcd.h"

// 分配命令完成结构
xhci_command_completion_t *xhci_alloc_command_completion(void) {
    xhci_command_completion_t *completion =
        (xhci_command_completion_t *)malloc(sizeof(xhci_command_completion_t));

    if (!completion) {
        return NULL;
    }

    memset(completion, 0, sizeof(xhci_command_completion_t));
    completion->status = COMPLETION_STATUS_PENDING;
    completion->lock.lock = 0;

    return completion;
}

// 释放命令完成结构
void xhci_free_command_completion(xhci_command_completion_t *completion) {
    if (!completion)
        return;

    free(completion);
}

extern void xhci_handle_events(xhci_hcd_t *xhci);

void dump_xhci_states(xhci_hcd_t *xhci, int port) {
    uint64_t crcr = xhci_readq(&xhci->op_regs->crcr);

    printk("CRCR Register: 0x%llx\n", crcr);
    printk("  CS (Command Stop): %d\n", !!(crcr & (1 << 1)));
    printk("  CA (Command Abort): %d\n", !!(crcr & (1 << 2)));
    printk("  CRR (Command Ring Running): %d\n", !!(crcr & (1 << 3)));

    if (!(crcr & (1 << 3))) {
        printk("\n[X] Command Ring NOT RUNNING!\n");
        printk("   Hardware stopped processing commands!\n");
    }

    uint32_t usbsts = xhci_readl(&xhci->op_regs->usbsts);

    printk("\nUSBSTS: 0x%08x\n", usbsts);
    printk("  HCHalted: %d %s\n", !!(usbsts & (1 << 0)),
           (usbsts & (1 << 0)) ? "[X] HALTED" : "[V] RUNNING");
    printk("  Host System Error: %d %s\n", !!(usbsts & (1 << 2)),
           (usbsts & (1 << 2)) ? "[X] ERROR" : "[V]");
    printk("  Event Interrupt: %d\n", !!(usbsts & (1 << 3)));
    printk("  Port Change Detect: %d\n", !!(usbsts & (1 << 4)));

    printk("XHCI port %d caused\n", port);
    printk("  portsc = %#010x\n", xhci->port_regs[port].portsc);
}

// 等待命令完成
int xhci_wait_for_command(xhci_command_completion_t *completion,
                          uint32_t timeout_ms) {
    if (!completion) {
        return -EINVAL;
    }

    uint64_t timeout = timeout_ms
                           ? ((uint64_t)timeout_ms * 1000000ULL + nanoTime())
                           : UINT64_MAX;

    spin_lock(&completion->lock);

    arch_enable_interrupt();

    while (completion->status == COMPLETION_STATUS_PENDING) {
        xhci_handle_events(completion->hcd);
        if (nanoTime() > timeout) {
            completion->status = COMPLETION_STATUS_TIMEOUT;
            printk("XHCI: Command timeout\n");
            dump_xhci_states(completion->hcd, completion->device->port);
            arch_disable_interrupt();
            spin_unlock(&completion->lock);
            return -ETIMEDOUT;
        }
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
    arch_disable_interrupt();

    completion_status_t status = completion->status;
    uint32_t code = completion->completion_code;

    spin_unlock(&completion->lock);

    if (status == COMPLETION_STATUS_SUCCESS) {
        return 0;
    } else {
        printk("XHCI: Command failed (status=%d, code=%d)\n", status, code);
        dump_xhci_states(completion->hcd, completion->device->port);
        return -EIO;
    }
}

// 分配传输完成结构
xhci_transfer_completion_t *xhci_alloc_transfer_completion(void) {
    xhci_transfer_completion_t *completion =
        (xhci_transfer_completion_t *)malloc(
            sizeof(xhci_transfer_completion_t));

    if (!completion) {
        return NULL;
    }

    memset(completion, 0, sizeof(xhci_transfer_completion_t));
    completion->status = COMPLETION_STATUS_PENDING;
    completion->lock.lock = 0;

    return completion;
}

// 释放传输完成结构
void xhci_free_transfer_completion(xhci_transfer_completion_t *completion) {
    if (!completion)
        return;

    free(completion);
}

// 等待传输完成
int xhci_wait_for_transfer(xhci_transfer_completion_t *completion,
                           uint32_t timeout_ms) {
    if (!completion) {
        return -EINVAL;
    }

    uint64_t timeout = timeout_ms
                           ? ((uint64_t)timeout_ms * 1000000ULL + nanoTime())
                           : UINT64_MAX;

    spin_lock(&completion->lock);

    arch_enable_interrupt();

    while (completion->status == COMPLETION_STATUS_PENDING) {
        xhci_handle_events(completion->hcd);
        if (nanoTime() > timeout) {
            completion->status = COMPLETION_STATUS_TIMEOUT;
            printk("XHCI: Transfer timeout\n");
            dump_xhci_states(completion->hcd,
                             completion->transfer->device->port);
            arch_disable_interrupt();
            spin_unlock(&completion->lock);
            return -ETIMEDOUT;
        }
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
    arch_disable_interrupt();

    completion_status_t status = completion->status;
    uint32_t code = completion->completion_code;
    uint32_t transferred = completion->transferred_length;

    spin_unlock(&completion->lock);

    if (status == COMPLETION_STATUS_SUCCESS) {
        return 0;
    } else {
        printk("XHCI: Transfer failed (status=%d, code=%d)\n", status, code);
        dump_xhci_states(completion->hcd, completion->transfer->device->port);
        return -EIO;
    }
}

// 跟踪命令
void xhci_track_command(xhci_hcd_t *xhci, xhci_trb_t *trb,
                        xhci_command_completion_t *completion,
                        uint32_t cmd_type) {
    xhci_command_tracker_t *tracker =
        (xhci_command_tracker_t *)malloc(sizeof(xhci_command_tracker_t));

    if (!tracker) {
        printk("XHCI: Failed to allocate command tracker\n");
        return;
    }

    completion->hcd = xhci;

    tracker->trb = trb;
    tracker->completion = completion;
    tracker->command_type = cmd_type;

    spin_lock(&xhci->tracker_mutex);
    tracker->next = xhci->pending_commands;
    xhci->pending_commands = tracker;
    spin_unlock(&xhci->tracker_mutex);

    printk("XHCI: Tracking command type %d at TRB %p\n", cmd_type, trb);
}

// 跟踪传输
void xhci_track_transfer(xhci_hcd_t *xhci, xhci_trb_t *first_trb, int trb_num,
                         xhci_transfer_completion_t *completion,
                         usb_transfer_t *transfer) {
    xhci_transfer_tracker_t *tracker =
        (xhci_transfer_tracker_t *)malloc(sizeof(xhci_transfer_tracker_t));

    if (!tracker) {
        printk("XHCI: Failed to allocate transfer tracker\n");
        return;
    }

    completion->hcd = xhci;

    tracker->first_trb = first_trb;
    tracker->trb_num = trb_num;
    tracker->completion = completion;
    tracker->transfer = transfer;

    spin_lock(&xhci->tracker_mutex);
    tracker->next = xhci->pending_transfers;
    xhci->pending_transfers = tracker;
    spin_unlock(&xhci->tracker_mutex);

    // printk("XHCI: Tracking transfer at TRB %p\n", first_trb);
}

// 完成命令
void xhci_complete_command(xhci_hcd_t *xhci, xhci_trb_t *event_trb) {
    uint64_t cmd_trb_addr = event_trb->parameter;
    uint32_t completion_code = (event_trb->status >> 24) & 0xFF;
    uint32_t slot_id = (event_trb->control >> 24) & 0xFF;

    spin_lock(&xhci->tracker_mutex);

    xhci_command_tracker_t **prev = &xhci->pending_commands;
    xhci_command_tracker_t *tracker = xhci->pending_commands;

    while (tracker) {
        if (translate_address(get_current_page_dir(false),
                              (uint64_t)tracker->trb) == cmd_trb_addr) {
            if (tracker->completion) {
                tracker->completion->completion_code = completion_code;
                tracker->completion->slot_id = slot_id;
                tracker->completion->result = event_trb->parameter;

                if (completion_code == 1 || completion_code == 13) { // SUCCESS
                    tracker->completion->status = COMPLETION_STATUS_SUCCESS;
                } else {
                    tracker->completion->status = COMPLETION_STATUS_ERROR;
                }
            }

            // 从列表中移除
            *prev = tracker->next;
            free(tracker);

            spin_unlock(&xhci->tracker_mutex);
            return;
        }

        prev = &tracker->next;
        tracker = tracker->next;
    }

    spin_unlock(&xhci->tracker_mutex);
    printk("XHCI: Warning - No matching command tracker found\n");
}

// 完成传输
void xhci_complete_transfer(xhci_hcd_t *xhci, xhci_trb_t *event_trb) {
    uint64_t transfer_trb_addr = event_trb->parameter;
    uint32_t completion_code = (event_trb->status >> 24) & 0xFF;
    uint32_t transfer_length = event_trb->status & 0xFFFFFF;

    spin_lock(&xhci->tracker_mutex);

    xhci_transfer_tracker_t **prev = &xhci->pending_transfers;
    xhci_transfer_tracker_t *tracker = xhci->pending_transfers;

    xhci_trb_t *ring_trb = (xhci_trb_t *)phys_to_virt(transfer_trb_addr);

    while (tracker) {
        // 检查是否匹配（需要检查TRB范围）
        if (tracker->completion) {
            if ((tracker->trb_num > 0 && ring_trb >= tracker->first_trb &&
                 ring_trb <= tracker->first_trb + tracker->trb_num) ||
                (tracker->trb_num < 0 &&
                 ring_trb >= tracker->first_trb - (-tracker->trb_num + 1) &&
                 ring_trb <= tracker->first_trb)) {
                tracker->completion->completion_code = completion_code;

                // transfer_length 是剩余未传输的字节数
                if (tracker->transfer) {
                    tracker->completion->transferred_length =
                        tracker->transfer->length - transfer_length;
                    tracker->transfer->actual_length =
                        tracker->completion->transferred_length;
                } else {
                    tracker->completion->transferred_length = 0;
                }

                if (completion_code == 1 ||
                    completion_code == 13) { // SUCCESS or SHORT_PACKET
                    tracker->completion->status = COMPLETION_STATUS_SUCCESS;
                    if (tracker->transfer) {
                        tracker->transfer->status = 0;
                    }
                } else {
                    tracker->completion->status = COMPLETION_STATUS_ERROR;
                    if (tracker->transfer) {
                        tracker->transfer->status = -EIO;
                    }
                }

                // 调用用户回调
                if (tracker->transfer && tracker->transfer->callback) {
                    tracker->transfer->callback(tracker->transfer);
                }

                // 从列表中移除
                *prev = tracker->next;
                free(tracker);

                spin_unlock(&xhci->tracker_mutex);
                return;
            }
        }

        prev = &tracker->next;
        tracker = tracker->next;
    }

    spin_unlock(&xhci->tracker_mutex);
    printk("XHCI: Warning - No matching transfer tracker found\n");
}
