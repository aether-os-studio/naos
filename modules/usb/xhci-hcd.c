// Rewrite version from seabios usb-xhci.c

#include "xhci-hcd.h"

#include <arch/arch.h>
#include <drivers/bus/msi.h>
#include <drivers/kernel_logger.h>
#include <irq/irq_manager.h>
#include <task/task.h>

#if defined(__x86_64__)
#include <arch/x64/core/normal.h>
extern uint32_t cpuid_to_lapicid[MAX_CPU_NUM];
#endif

#define XHCI_RING_ITEMS 128
#define XHCI_RING_SIZE (XHCI_RING_ITEMS * sizeof(struct xhci_trb))
#define XHCI_TRB_MAX_XFER 65536
#define XHCI_EVENT_POLL_NS (5ULL * 1000ULL * 1000ULL)
#define XHCI_IMAN_IP (1U << 0)
#define XHCI_IMAN_IE (1U << 1)

#define XHCI_CMD_RS (1 << 0)
#define XHCI_CMD_HCRST (1 << 1)
#define XHCI_CMD_INTE (1 << 2)

#define XHCI_STS_HCH (1 << 0)
#define XHCI_STS_EINT (1 << 3)
#define XHCI_STS_CNR (1 << 11)

#define XHCI_PORTSC_CCS (1 << 0)
#define XHCI_PORTSC_PED (1 << 1)
#define XHCI_PORTSC_PR (1 << 4)
#define XHCI_PORTSC_PLS_SHIFT 5
#define XHCI_PORTSC_PLS_MASK 0xf
#define XHCI_PORTSC_PP (1 << 9)
#define XHCI_PORTSC_SPEED_SHIFT 10
#define XHCI_PORTSC_SPEED_MASK 0xf
#define XHCI_PORTSC_CSC (1 << 17)
#define XHCI_PORTSC_PEC (1 << 18)
#define XHCI_PORTSC_WRC (1 << 19)
#define XHCI_PORTSC_OCC (1 << 20)
#define XHCI_PORTSC_PRC (1 << 21)
#define XHCI_PORTSC_PLC (1 << 22)
#define XHCI_PORTSC_CEC (1 << 23)

#define XHCI_PORTSC_CHANGE_BITS                                                \
    (XHCI_PORTSC_CSC | XHCI_PORTSC_PEC | XHCI_PORTSC_WRC | XHCI_PORTSC_OCC |   \
     XHCI_PORTSC_PRC | XHCI_PORTSC_PLC | XHCI_PORTSC_CEC)

#define XHCI_HCS1_MAX_SLOTS_MASK 0xff
#define XHCI_HCS1_MAX_INTRS_SHIFT 8
#define XHCI_HCS1_MAX_INTRS_MASK 0x7ff
#define XHCI_HCS1_MAX_PORTS_SHIFT 24
#define XHCI_HCS1_MAX_PORTS_MASK 0xff

#define TRB_C (1 << 0)
#define TRB_TYPE_SHIFT 10
#define TRB_TYPE_MASK 0x3f
#define TRB_TYPE(t) (((t) >> TRB_TYPE_SHIFT) & TRB_TYPE_MASK)
#define TRB_CC(status) (((status) >> 24) & 0xff)

#define TRB_TR_CH (1 << 4)
#define TRB_TR_IOC (1 << 5)
#define TRB_TR_IDT (1 << 6)
#define TRB_TR_DIR (1 << 16)

#define TRB_CR_SLOTID_SHIFT 24
#define TRB_CR_SLOTID_MASK 0xff
#define TRB_CR_EPID_SHIFT 16
#define TRB_CR_EPID_MASK 0x1f

#define TRB_LK_TC (1 << 1)

#define TRB_INTR_SHIFT 22
#define TRB_INTR_MASK 0x3ff

#define xhci_get_field(data, field) (((data) >> field##_SHIFT) & field##_MASK)

typedef enum TRBType {
    TRB_RESERVED = 0,
    TR_NORMAL,
    TR_SETUP,
    TR_DATA,
    TR_STATUS,
    TR_ISOCH,
    TR_LINK,
    TR_EVDATA,
    TR_NOOP,
    CR_ENABLE_SLOT,
    CR_DISABLE_SLOT,
    CR_ADDRESS_DEVICE,
    CR_CONFIGURE_ENDPOINT,
    CR_EVALUATE_CONTEXT,
    CR_RESET_ENDPOINT,
    CR_STOP_ENDPOINT,
    CR_SET_TR_DEQUEUE,
    CR_RESET_DEVICE,
    CR_FORCE_EVENT,
    CR_NEGOTIATE_BW,
    CR_SET_LATENCY_TOLERANCE,
    CR_GET_PORT_BANDWIDTH,
    CR_FORCE_HEADER,
    CR_NOOP,
    ER_TRANSFER = 32,
    ER_COMMAND_COMPLETE,
    ER_PORT_STATUS_CHANGE,
    ER_BANDWIDTH_REQUEST,
    ER_DOORBELL,
    ER_HOST_CONTROLLER,
    ER_DEVICE_NOTIFICATION,
    ER_MFINDEX_WRAP,
} TRBType;

typedef enum TRBCCode {
    CC_INVALID = 0,
    CC_SUCCESS,
    CC_DATA_BUFFER_ERROR,
    CC_BABBLE_DETECTED,
    CC_USB_TRANSACTION_ERROR,
    CC_TRB_ERROR,
    CC_STALL_ERROR,
    CC_RESOURCE_ERROR,
    CC_BANDWIDTH_ERROR,
    CC_NO_SLOTS_ERROR,
    CC_INVALID_STREAM_TYPE_ERROR,
    CC_SLOT_NOT_ENABLED_ERROR,
    CC_EP_NOT_ENABLED_ERROR,
    CC_SHORT_PACKET,
    CC_RING_UNDERRUN,
    CC_RING_OVERRUN,
    CC_VF_ER_FULL,
    CC_PARAMETER_ERROR,
    CC_BANDWIDTH_OVERRUN,
    CC_CONTEXT_STATE_ERROR,
    CC_NO_PING_RESPONSE_ERROR,
    CC_EVENT_RING_FULL_ERROR,
    CC_INCOMPATIBLE_DEVICE_ERROR,
    CC_MISSED_SERVICE_ERROR,
    CC_COMMAND_RING_STOPPED,
    CC_COMMAND_ABORTED,
    CC_STOPPED,
    CC_STOPPED_LENGTH_INVALID,
    CC_MAX_EXIT_LATENCY_TOO_LARGE_ERROR = 29,
    CC_ISOCH_BUFFER_OVERRUN = 31,
    CC_EVENT_LOST_ERROR,
    CC_UNDEFINED_ERROR,
    CC_INVALID_STREAM_ID_ERROR,
    CC_SECONDARY_BANDWIDTH_ERROR,
    CC_SPLIT_TRANSACTION_ERROR
} TRBCCode;

enum {
    PLS_U0 = 0,
    PLS_DISABLED = 4,
    PLS_POLLING = 7,
};

struct xhci_ring {
    struct xhci_trb *trbs;
    uint32_t nidx;
    uint32_t eidx;
    uint32_t cs;
    struct xhci_trb evt;
};

struct xhci_portmap {
    uint8_t start;
    uint8_t count;
};

typedef struct usb_xhci usb_xhci_t;
typedef struct xhci_ring xhci_ring_t;
typedef struct xhci_portmap xhci_portmap_t;
typedef struct xhci_event_ring xhci_event_ring_t;
typedef struct xhci_pipe xhci_pipe_t;

struct xhci_event_ring {
    struct xhci_ring ring;
    xhci_event_ring_seg_t *eseg;
    xhci_interrupter_regs_t *ir;
    usb_xhci_t *xhci;
    struct msi_desc_t msi;
    uint16_t irq_vector;
    uint16_t id;
    volatile bool pending;
};

struct xhci_pipe {
    struct xhci_ring reqs;
    usb_pipe_t pipe;
    uint32_t slotid;
    uint32_t epid;
    uint16_t interrupter;
    int transfer_count;
    intr_xfer_cb intr_xfer;
    void *intr_xfer_data;
};

struct usb_xhci {
    usb_controller_t usb;

    pci_device_t *pci_dev;

    uint32_t xcap;
    uint32_t ports;
    uint32_t slots;
    uint32_t max_intrs;
    uint8_t context64;
    struct xhci_portmap usb2;
    struct xhci_portmap usb3;

    xhci_caps_t *caps;
    xhci_op_t *op;
    xhci_port_regs_t *pr;
    xhci_db_t *db;

    xhci_dev_ctx_entry_t *devs;
    struct xhci_ring cmds;
    struct xhci_event_ring *intrs;
    uint32_t intr_count;
    uint32_t rr_intr;

    struct xhci_pipe ***pipes;

    spinlock_t event_lock;
    task_t *event_task;
    bool running;

#define XHCI_QUIRK_VL805_OLD_REV (1UL << 0)
    uint64_t quirks;
};

static const char *speed_name[16] = {
    [0] = " - ", [1] = "Full", [2] = "Low", [3] = "High", [4] = "Super",
};

static const int speed_from_xhci[16] = {
    [0] = -1,
    [1] = USB_FULLSPEED,
    [2] = USB_LOWSPEED,
    [3] = USB_HIGHSPEED,
    [4] = USB_SUPERSPEED,
    [5 ... 15] = -1,
};

static const int speed_to_xhci[] = {
    [USB_FULLSPEED] = 1,
    [USB_LOWSPEED] = 2,
    [USB_HIGHSPEED] = 3,
    [USB_SUPERSPEED] = 4,
};

static inline void delay(uint64_t ms) {
    uint64_t timeout = nano_time() + ms * 1000000ULL;
    while (nano_time() < timeout)
        arch_pause();
}

static int wait_bit(volatile uint32_t *reg, uint32_t mask, uint32_t value,
                    uint32_t timeout_ms) {
    uint64_t timeout = nano_time() + (uint64_t)timeout_ms * 1000000ULL;
    while ((readl((const void *)reg) & mask) != value) {
        if (nano_time() > timeout)
            return -ETIMEDOUT;
        arch_pause();
    }
    return 0;
}

static uint32_t xhci_trb_status(uint32_t xferlen, uint16_t intr_target) {
    return (xferlen & 0x1ffffU) |
           (((uint32_t)intr_target & TRB_INTR_MASK) << TRB_INTR_SHIFT);
}

static uint64_t xhci_virt_to_phys(const void *ptr) {
    return translate_address(get_current_page_dir(false), (uint64_t)ptr);
}

static int xhci_alloc_ring(struct xhci_ring *ring) {
    memset(ring, 0, sizeof(*ring));
    ring->trbs = alloc_frames_bytes_dma32(XHCI_RING_SIZE);
    if (!ring->trbs)
        return -ENOMEM;
    memset(ring->trbs, 0, XHCI_RING_SIZE);
    dma_sync_cpu_to_device(ring->trbs, XHCI_RING_SIZE);
    ring->cs = 1;
    return 0;
}

static void xhci_free_ring(struct xhci_ring *ring) {
    if (!ring || !ring->trbs)
        return;
    free_frames_bytes_dma32(ring->trbs, XHCI_RING_SIZE);
    ring->trbs = NULL;
}

static void xhci_doorbell(usb_xhci_t *xhci, uint32_t slotid, uint32_t value) {
    dma_mb();
    writel(&xhci->db[slotid].doorbell, value);
    dma_mb();
}

static xhci_interrupter_regs_t *xhci_ir_ptr(usb_xhci_t *xhci, uint32_t idx) {
    uint8_t *base = (uint8_t *)xhci->caps;
    return (struct xhci_ir *)(base + readl(&xhci->caps->rtsoff) + 0x20 +
                              idx * 0x20);
}

static uint32_t xhci_max_scratchpad(uint32_t hcsparams2) {
    return ((hcsparams2 >> 27) & 0x1f) | (((hcsparams2 >> 21) & 0x1f) << 5);
}

static void xhci_print_port_state(const char *prefix, uint32_t port,
                                  uint32_t portsc) {
    uint32_t pls = xhci_get_field(portsc, XHCI_PORTSC_PLS);
    uint32_t speed = xhci_get_field(portsc, XHCI_PORTSC_SPEED);

    printk("%s port #%u: 0x%08x,%s%s pls %u, speed %u [%s]\n", prefix, port + 1,
           portsc, (portsc & XHCI_PORTSC_PP) ? " powered," : "",
           (portsc & XHCI_PORTSC_PED) ? " enabled," : "", pls, speed,
           speed_name[speed]);
}

static void xhci_ack_port_change(usb_xhci_t *xhci, uint32_t port) {
    uint32_t portsc = readl(&xhci->pr[port].portsc);
    uint32_t clear = portsc & XHCI_PORTSC_CHANGE_BITS;
    if (clear)
        writel(&xhci->pr[port].portsc, clear);
}

static int xhci_hub_detect(usb_hub_t *hub, uint32_t port) {
    usb_xhci_t *xhci = container_of(hub->cntl, usb_xhci_t, usb);
    uint32_t portsc = readl(&xhci->pr[port].portsc);
    return (portsc & XHCI_PORTSC_CCS) ? 1 : 0;
}

static int xhci_hub_reset(usb_hub_t *hub, uint32_t port) {
    usb_xhci_t *xhci = container_of(hub->cntl, usb_xhci_t, usb);
    uint32_t portsc = readl(&xhci->pr[port].portsc);

    if (!(portsc & XHCI_PORTSC_CCS))
        return -1;

    if (!(portsc & XHCI_PORTSC_PED) ||
        xhci_get_field(portsc, XHCI_PORTSC_PLS) == PLS_POLLING) {
        writel(&xhci->pr[port].portsc, portsc | XHCI_PORTSC_PR);
    }

    uint64_t timeout = nano_time() + 2000000000ULL;
    while (nano_time() < timeout) {
        portsc = readl(&xhci->pr[port].portsc);
        if (!(portsc & XHCI_PORTSC_CCS))
            return -1;
        if (!(portsc & XHCI_PORTSC_PR) && (portsc & XHCI_PORTSC_PED))
            break;
        arch_pause();
    }

    if (!(portsc & XHCI_PORTSC_PED))
        return -1;

    xhci_ack_port_change(xhci, port);
    delay(USB_TIME_RSTRCY);
    xhci_print_port_state("xhci", port, portsc);

    return speed_from_xhci[xhci_get_field(portsc, XHCI_PORTSC_SPEED)];
}

static int xhci_hub_portmap(usb_hub_t *hub, uint32_t vport) {
    usb_xhci_t *xhci = container_of(hub->cntl, usb_xhci_t, usb);
    uint32_t pport = vport + 1;

    if (vport + 1 >= xhci->usb3.start &&
        vport + 1 < xhci->usb3.start + xhci->usb3.count)
        pport = vport + 2 - xhci->usb3.start;

    if (vport + 1 >= xhci->usb2.start &&
        vport + 1 < xhci->usb2.start + xhci->usb2.count)
        pport = vport + 2 - xhci->usb2.start;

    return pport;
}

static void xhci_hub_disconnect(usb_hub_t *hub, uint32_t port) {
    usb_xhci_t *xhci = container_of(hub->cntl, usb_xhci_t, usb);
    xhci_ack_port_change(xhci, port);
}

static usb_hub_ops_t xhci_hub_ops = {
    .detect = xhci_hub_detect,
    .reset = xhci_hub_reset,
    .portmap = xhci_hub_portmap,
    .disconnect = xhci_hub_disconnect,
    .realloc_pipe = xhci_realloc_pipe,
    .send_pipe = xhci_send_pipe,
    .send_intr_pipe = xhci_send_intr_pipe,
};

static int xhci_cc_to_status(uint32_t completion_code) {
    switch (completion_code) {
    case CC_SUCCESS:
        return EVENT_SUCCESS;
    case CC_SHORT_PACKET:
        return EVENT_SHORT_PACKET;
    case CC_STALL_ERROR:
        return EVENT_STALL;
    case CC_BABBLE_DETECTED:
        return EVENT_BABBLE;
    case CC_USB_TRANSACTION_ERROR:
    case CC_TRB_ERROR:
    default:
        return EVENT_ERROR;
    }
}

static bool xhci_ring_busy(struct xhci_ring *ring) {
    return ring->eidx != ring->nidx;
}

static void xhci_trb_fill(struct xhci_ring *ring, void *data, uint32_t status,
                          uint32_t flags) {
    struct xhci_trb *dst = &ring->trbs[ring->nidx];

    memset(dst, 0, sizeof(*dst));
    if (flags & TRB_TR_IDT) {
        memcpy(&dst->ptr_low, data, status & 0xff);
    } else {
        uint64_t phys = data ? xhci_virt_to_phys(data) : 0;
        dst->ptr_low = phys;
        dst->ptr_high = phys >> 32;
    }

    dst->status = status;
    __sync_synchronize();
    dst->control = flags | (ring->cs ? TRB_C : 0);
    dma_sync_cpu_to_device(dst, sizeof(*dst));
}

static void xhci_trb_fill_phys(struct xhci_ring *ring, uint64_t phys,
                               uint32_t status, uint32_t flags) {
    struct xhci_trb *dst = &ring->trbs[ring->nidx];

    memset(dst, 0, sizeof(*dst));
    dst->ptr_low = (uint32_t)phys;
    dst->ptr_high = (uint32_t)(phys >> 32);
    dst->status = status;
    __sync_synchronize();
    dst->control = flags | (ring->cs ? TRB_C : 0);
    dma_sync_cpu_to_device(dst, sizeof(*dst));
}

static void xhci_ring_wrap(struct xhci_ring *ring) {
    xhci_trb_fill(ring, ring->trbs, 0, (TR_LINK << TRB_TYPE_SHIFT) | TRB_LK_TC);
    ring->nidx = 0;
    ring->cs = !ring->cs;
}

static void xhci_trb_queue(struct xhci_ring *ring, void *data, uint32_t status,
                           uint32_t flags) {
    if (ring->nidx >= XHCI_RING_ITEMS - 1)
        xhci_ring_wrap(ring);

    xhci_trb_fill(ring, data, status, flags);
    ring->nidx++;
}

static void xhci_trb_queue_phys(struct xhci_ring *ring, uint64_t phys,
                                uint32_t status, uint32_t flags) {
    if (ring->nidx >= XHCI_RING_ITEMS - 1)
        xhci_ring_wrap(ring);

    xhci_trb_fill_phys(ring, phys, status, flags);
    ring->nidx++;
}

static uint32_t xhci_bytes_to_64kb_boundary(uint64_t phys_addr) {
    return 0x10000 - (phys_addr & 0xffff);
}

static void xhci_trb_queue_split(struct xhci_ring *ring, void *data,
                                 int datalen, uint32_t flags,
                                 uint16_t intr_target, bool is_last_in_td) {
    uint32_t offset = 0;
    uint64_t *pgd = get_current_page_dir(false);

    while (offset < (uint32_t)datalen) {
        uint64_t va = (uint64_t)data + offset;
        uint64_t phys = translate_address(pgd, va);
        uint32_t remaining = datalen - offset;
        uint32_t page_left = DEFAULT_PAGE_SIZE - (va & (DEFAULT_PAGE_SIZE - 1));
        uint32_t boundary_left = xhci_bytes_to_64kb_boundary(phys);
        uint32_t chunk = remaining;
        uint32_t chunk_flags = flags;

        if (chunk > page_left)
            chunk = page_left;
        if (chunk > boundary_left)
            chunk = boundary_left;
        if (chunk > XHCI_TRB_MAX_XFER)
            chunk = XHCI_TRB_MAX_XFER;

        bool last_chunk = offset + chunk >= (uint32_t)datalen;
        if (!last_chunk || !is_last_in_td)
            chunk_flags = (flags & ~TRB_TR_IOC) | TRB_TR_CH;

        xhci_trb_queue_phys(ring, phys, xhci_trb_status(chunk, intr_target),
                            chunk_flags);
        offset += chunk;
    }
}

static struct xhci_pipe *xhci_find_pipe(usb_xhci_t *xhci, uint32_t slotid,
                                        uint32_t epid) {
    if (slotid == 0 || slotid > xhci->slots || epid >= 32)
        return NULL;
    return xhci->pipes[slotid][epid];
}

static void xhci_commit_erdp(usb_xhci_t *xhci, struct xhci_event_ring *intr) {
    uint64_t erdp = xhci_virt_to_phys(&intr->ring.trbs[intr->ring.nidx]);

    writel(&intr->ir->erdp_low, (uint32_t)(erdp & ~0xfU) | (1 << 3));
    writel(&intr->ir->erdp_high, erdp >> 32);

    if (xhci->quirks & XHCI_QUIRK_VL805_OLD_REV) {
        uint32_t low = readl(&intr->ir->erdp_low);
        uint32_t high = readl(&intr->ir->erdp_high);
        writel(&intr->ir->erdp_low, low);
        writel(&intr->ir->erdp_high, high);
        writel(&intr->ir->iman, XHCI_IMAN_IP | XHCI_IMAN_IE);
    }
}

static bool xhci_event_ring_has_event(struct xhci_event_ring *intr) {
    struct xhci_trb *etrb = &intr->ring.trbs[intr->ring.nidx];

    dma_sync_device_to_cpu(etrb, sizeof(*etrb));
    return !!(readl(&etrb->control) & TRB_C) == intr->ring.cs;
}

static void xhci_process_event_ring(struct xhci_event_ring *intr) {
    usb_xhci_t *xhci = intr->xhci;
    uint32_t processed = 0;

    while (xhci_event_ring_has_event(intr)) {
        struct xhci_trb *etrb = &intr->ring.trbs[intr->ring.nidx];
        uint32_t type = TRB_TYPE(readl(&etrb->control));
        uint32_t cc = TRB_CC(readl(&etrb->status));

        switch (type) {
        case ER_TRANSFER: {
            uint32_t slotid =
                xhci_get_field(readl(&etrb->control), TRB_CR_SLOTID);
            uint32_t epid = xhci_get_field(readl(&etrb->control), TRB_CR_EPID);
            struct xhci_pipe *pipe = xhci_find_pipe(xhci, slotid, epid);

            if (pipe) {
                uint64_t ptr = ((uint64_t)readl(&etrb->ptr_high) << 32) |
                               readl(&etrb->ptr_low);
                struct xhci_trb *first = (struct xhci_trb *)phys_to_virt(
                    xhci_virt_to_phys((void *)pipe->reqs.trbs));
                struct xhci_trb *last = (struct xhci_trb *)phys_to_virt(ptr);

                memcpy(&pipe->reqs.evt, etrb, sizeof(*etrb));
                pipe->reqs.eidx = (uint32_t)(last - first) + 1;

                if (pipe->pipe.eptype == USB_ENDPOINT_XFER_INT &&
                    pipe->intr_xfer) {
                    pipe->intr_xfer(xhci_cc_to_status(cc),
                                    pipe->intr_xfer_data);
                }
            }
            break;
        }
        case ER_COMMAND_COMPLETE: {
            uint64_t ptr = ((uint64_t)etrb->ptr_high << 32) | etrb->ptr_low;
            struct xhci_trb *cmd = (struct xhci_trb *)phys_to_virt(ptr);

            memcpy(&xhci->cmds.evt, etrb, sizeof(*etrb));
            xhci->cmds.eidx = (uint32_t)(cmd - xhci->cmds.trbs) + 1;
            break;
        }
        case ER_PORT_STATUS_CHANGE: {
            uint32_t port = ((etrb->ptr_low >> 24) & 0xff) - 1;
            xhci_ack_port_change(xhci, port);
            if (xhci->usb.roothub)
                usb_hub_mark_port_changed(xhci->usb.roothub, port);
            break;
        }
        default:
            printk("xhci: unhandled event type %u cc %u\n", type, cc);
            break;
        }

        intr->ring.nidx++;
        if (intr->ring.nidx >= XHCI_RING_ITEMS) {
            intr->ring.nidx = 0;
            intr->ring.cs = !intr->ring.cs;
        }
        processed++;
    }

    if (processed)
        xhci_commit_erdp(xhci, intr);

    intr->pending = false;
}

static void xhci_process_events(usb_xhci_t *xhci) {
    spin_lock(&xhci->event_lock);
    for (uint32_t i = 0; i < xhci->intr_count; i++) {
        if (xhci->intrs[i].pending ||
            xhci_event_ring_has_event(&xhci->intrs[i]))
            xhci_process_event_ring(&xhci->intrs[i]);
    }
    spin_unlock(&xhci->event_lock);
}

static int xhci_event_wait(usb_xhci_t *xhci, struct xhci_ring *ring,
                           uint32_t timeout_ms) {
    uint64_t timeout = nano_time() + (uint64_t)timeout_ms * 1000000ULL;

    while (nano_time() < timeout) {
        xhci_process_events(xhci);
        if (!xhci_ring_busy(ring))
            return TRB_CC(ring->evt.status);
        schedule(SCHED_FLAG_YIELD);
    }

    ring->eidx = ring->nidx;
    return CC_USB_TRANSACTION_ERROR;
}

static int xhci_cmd_submit(usb_xhci_t *xhci, xhci_input_ctx_t *inctx,
                           uint32_t flags) {
    if (inctx) {
        dma_sync_cpu_to_device(inctx, (sizeof(struct xhci_inctx) * 33)
                                          << xhci->context64);
    }

    xhci_trb_queue(&xhci->cmds, inctx, xhci_trb_status(0, 0), flags);
    xhci_doorbell(xhci, 0, 0);
    return xhci_event_wait(xhci, &xhci->cmds, 1000);
}

static int xhci_cmd_enable_slot(usb_xhci_t *xhci) {
    int cc = xhci_cmd_submit(xhci, NULL, CR_ENABLE_SLOT << TRB_TYPE_SHIFT);
    if (cc != CC_SUCCESS)
        return -1;
    return (xhci->cmds.evt.control >> 24) & 0xff;
}

static int xhci_cmd_disable_slot(usb_xhci_t *xhci, uint32_t slotid) {
    return xhci_cmd_submit(xhci, NULL,
                           (CR_DISABLE_SLOT << TRB_TYPE_SHIFT) |
                               (slotid << TRB_CR_SLOTID_SHIFT));
}

static int xhci_cmd_address_device(usb_xhci_t *xhci, uint32_t slotid,
                                   xhci_input_ctx_t *inctx) {
    return xhci_cmd_submit(xhci, inctx,
                           (CR_ADDRESS_DEVICE << TRB_TYPE_SHIFT) |
                               (slotid << TRB_CR_SLOTID_SHIFT));
}

static int xhci_cmd_configure_endpoint(usb_xhci_t *xhci, uint32_t slotid,
                                       xhci_input_ctx_t *inctx) {
    return xhci_cmd_submit(xhci, inctx,
                           (CR_CONFIGURE_ENDPOINT << TRB_TYPE_SHIFT) |
                               (slotid << TRB_CR_SLOTID_SHIFT));
}

static int xhci_cmd_evaluate_context(usb_xhci_t *xhci, uint32_t slotid,
                                     xhci_input_ctx_t *inctx) {
    return xhci_cmd_submit(xhci, inctx,
                           (CR_EVALUATE_CONTEXT << TRB_TYPE_SHIFT) |
                               (slotid << TRB_CR_SLOTID_SHIFT));
}

static xhci_input_ctx_t *xhci_alloc_inctx(usb_device_t *usbdev, int maxepid) {
    usb_xhci_t *xhci = container_of(usbdev->hub->cntl, usb_xhci_t, usb);
    size_t size = (sizeof(struct xhci_inctx) * 33) << xhci->context64;
    xhci_input_ctx_t *in = alloc_frames_bytes_dma32(size);
    xhci_slot_ctx_t *slot;
    usb_device_t *iter;

    if (!in)
        return NULL;

    memset(in, 0, size);

    slot = (void *)&in[1 << xhci->context64];
    slot->ctx[0] |= maxepid << 27;
    slot->ctx[0] |= speed_to_xhci[usbdev->speed] << 20;

    iter = usbdev;
    if (usbdev->hub->usbdev && !usbdev->hub->usbdev->is_root_hub) {
        uint32_t route = 0;

        if (usbdev->speed == USB_LOWSPEED || usbdev->speed == USB_FULLSPEED) {
            usb_device_t *hubdev = usbdev->hub->usbdev;
            struct xhci_pipe *hpipe =
                container_of(hubdev->defpipe, struct xhci_pipe, pipe);

            if (hubdev->speed == USB_HIGHSPEED) {
                slot->ctx[2] |= hpipe->slotid;
                slot->ctx[2] |= (usbdev->port + 1) << 8;
            } else {
                xhci_slot_ctx_t *hslot = (void *)phys_to_virt(
                    ((uint64_t)xhci->devs[hpipe->slotid].ptr_high << 32) |
                    xhci->devs[hpipe->slotid].ptr_low);
                slot->ctx[2] = hslot->ctx[2];
            }
        }

        while (iter->hub && iter->hub->usbdev &&
               !iter->hub->usbdev->is_root_hub) {
            route <<= 4;
            route |= (iter->port + 1) & 0xf;
            iter = iter->hub->usbdev;
        }
        slot->ctx[0] |= route;
    }

    slot->ctx[1] |= (usbdev->port + 1) << 16;
    return in;
}

static int xhci_config_hub(usb_hub_t *hub) {
    usb_xhci_t *xhci = container_of(hub->cntl, usb_xhci_t, usb);
    struct xhci_pipe *pipe =
        container_of(hub->usbdev->defpipe, struct xhci_pipe, pipe);
    xhci_slot_ctx_t *hdslot = (void *)phys_to_virt(
        ((uint64_t)xhci->devs[pipe->slotid].ptr_high << 32) |
        xhci->devs[pipe->slotid].ptr_low);

    if ((hdslot->ctx[3] >> 27) == 3)
        return 0;

    xhci_input_ctx_t *in = xhci_alloc_inctx(hub->usbdev, 1);
    if (!in)
        return -ENOMEM;

    in->add = 0x01;
    xhci_slot_ctx_t *slot = (void *)&in[1 << xhci->context64];
    slot->ctx[0] |= 1 << 26;
    slot->ctx[1] |= hub->portcount << 24;

    int cc = xhci_cmd_configure_endpoint(xhci, pipe->slotid, in);
    free_frames_bytes_dma32(in, (sizeof(struct xhci_inctx) * 33)
                                    << xhci->context64);
    return cc == CC_SUCCESS ? 0 : -EIO;
}

static uint16_t xhci_pick_interrupter(usb_xhci_t *xhci, uint8_t eptype) {
    if (xhci->intr_count <= 1 || eptype == USB_ENDPOINT_XFER_CONTROL)
        return 0;

    uint32_t span = xhci->intr_count - 1;
    return (xhci->rr_intr++ % span) + 1;
}

static usb_pipe_t *
xhci_alloc_pipe(usb_device_t *usbdev, usb_endpoint_descriptor_t *epdesc,
                usb_super_speed_endpoint_descriptor_t *ss_epdesc) {
    usb_xhci_t *xhci = container_of(usbdev->hub->cntl, usb_xhci_t, usb);
    struct xhci_pipe *pipe;
    xhci_input_ctx_t *in = NULL;
    uint32_t epid;
    uint8_t eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;

    if (epdesc->bEndpointAddress == 0) {
        epid = 1;
    } else {
        epid = (epdesc->bEndpointAddress & 0x0f) * 2;
        if (epdesc->bEndpointAddress & USB_DIR_IN)
            epid++;
    }

    pipe = alloc_frames_bytes_dma32(sizeof(*pipe));
    if (!pipe)
        return NULL;
    memset(pipe, 0, sizeof(*pipe));

    usb_desc2pipe(&pipe->pipe, usbdev, epdesc);
    pipe->epid = epid;
    pipe->interrupter = xhci_pick_interrupter(xhci, eptype);

    if (xhci_alloc_ring(&pipe->reqs) != 0)
        goto fail;

    in = xhci_alloc_inctx(usbdev, epid);
    if (!in)
        goto fail;

    in->add = 0x01 | (1U << epid);

    xhci_ep_ctx_t *ep = (void *)&in[(pipe->epid + 1) << xhci->context64];
    if (eptype == USB_ENDPOINT_XFER_INT)
        ep->ctx[0] = (usb_get_period(usbdev, epdesc) + 3) << 16;
    ep->ctx[1] |= eptype << 3;
    if ((epdesc->bEndpointAddress & USB_DIR_IN) ||
        eptype == USB_ENDPOINT_XFER_CONTROL)
        ep->ctx[1] |= 1 << 5;
    ep->ctx[1] |= (uint32_t)pipe->pipe.maxpacket << 16;

    uint8_t max_burst = 0;
    if (usbdev->speed == USB_SUPERSPEED && ss_epdesc)
        max_burst = ss_epdesc->bMaxBurst;
    else if (usbdev->speed == USB_HIGHSPEED &&
             (eptype == USB_ENDPOINT_XFER_ISOC ||
              eptype == USB_ENDPOINT_XFER_INT))
        max_burst = (pipe->pipe.maxpacket >> 11) & 0x3;

    uint64_t deq = xhci_virt_to_phys(pipe->reqs.trbs);
    ep->ctx[1] |= (uint32_t)max_burst << 8;
    ep->ctx[1] |= 3 << 1;
    ep->deq_low = (uint32_t)deq | 1;
    ep->deq_high = deq >> 32;
    ep->length = pipe->pipe.maxpacket;
    if (eptype == USB_ENDPOINT_XFER_CONTROL)
        ep->length |= 8;
    else if (eptype == USB_ENDPOINT_XFER_INT)
        ep->length |= 1024;
    else
        ep->length |= 3072;

    if (pipe->epid == 1) {
        if (usbdev->hub->usbdev && !usbdev->hub->usbdev->is_root_hub &&
            xhci_config_hub(usbdev->hub) != 0)
            goto fail;

        size_t ctx_size = (sizeof(struct xhci_slotctx) * 32) << xhci->context64;
        xhci_slot_ctx_t *dev = alloc_frames_bytes_dma32(ctx_size);
        if (!dev)
            goto fail;

        int slotid = xhci_cmd_enable_slot(xhci);
        if (slotid < 0) {
            free_frames_bytes_dma32(dev, ctx_size);
            goto fail;
        }

        memset(dev, 0, ctx_size);
        dma_sync_cpu_to_device(dev, ctx_size);

        uint64_t dcba = xhci_virt_to_phys(dev);
        xhci->devs[slotid].ptr_low = (uint32_t)dcba;
        xhci->devs[slotid].ptr_high = dcba >> 32;
        dma_sync_cpu_to_device(&xhci->devs[slotid], sizeof(xhci->devs[slotid]));

        if (xhci_cmd_address_device(xhci, slotid, in) != CC_SUCCESS) {
            xhci_cmd_disable_slot(xhci, slotid);
            free_frames_bytes_dma32(dev, ctx_size);
            goto fail;
        }

        pipe->slotid = slotid;
        usbdev->devaddr = slotid;
    } else {
        struct xhci_pipe *defpipe =
            container_of(usbdev->defpipe, struct xhci_pipe, pipe);
        pipe->slotid = defpipe->slotid;

        if (xhci_cmd_configure_endpoint(xhci, pipe->slotid, in) != CC_SUCCESS)
            goto fail;
    }

    free_frames_bytes_dma32(in, (sizeof(struct xhci_inctx) * 33)
                                    << xhci->context64);
    xhci->pipes[pipe->slotid][pipe->epid] = pipe;
    return &pipe->pipe;

fail:
    if (in) {
        free_frames_bytes_dma32(in, (sizeof(struct xhci_inctx) * 33)
                                        << xhci->context64);
    }
    xhci_free_ring(&pipe->reqs);
    free_frames_bytes_dma32(pipe, sizeof(*pipe));
    return NULL;
}

usb_pipe_t *
xhci_realloc_pipe(usb_device_t *usbdev, usb_pipe_t *upipe,
                  usb_endpoint_descriptor_t *epdesc,
                  usb_super_speed_endpoint_descriptor_t *ss_epdesc) {
    if (!epdesc) {
        struct xhci_pipe *pipe = container_of(upipe, struct xhci_pipe, pipe);
        usb_xhci_t *xhci = container_of(upipe->cntl, usb_xhci_t, usb);
        xhci->pipes[pipe->slotid][pipe->epid] = NULL;
        usb_add_freelist(upipe);
        return NULL;
    }

    if (!upipe)
        return xhci_alloc_pipe(usbdev, epdesc, ss_epdesc);

    int oldmaxpacket = upipe->maxpacket;
    usb_desc2pipe(upipe, usbdev, epdesc);
    if ((epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) !=
            USB_ENDPOINT_XFER_CONTROL ||
        upipe->maxpacket == oldmaxpacket)
        return upipe;

    struct xhci_pipe *pipe = container_of(upipe, struct xhci_pipe, pipe);
    usb_xhci_t *xhci = container_of(upipe->cntl, usb_xhci_t, usb);
    xhci_input_ctx_t *in = xhci_alloc_inctx(usbdev, 1);
    if (!in)
        return upipe;

    in->add = 1 << 1;
    xhci_ep_ctx_t *ep = (void *)&in[2 << xhci->context64];
    ep->ctx[1] |= pipe->pipe.maxpacket << 16;
    xhci_cmd_evaluate_context(xhci, pipe->slotid, in);
    free_frames_bytes_dma32(in, (sizeof(struct xhci_inctx) * 33)
                                    << xhci->context64);
    return upipe;
}

static void xhci_xfer_setup(struct xhci_pipe *pipe, int dir, void *cmd,
                            void *data, int datalen) {
    usb_xhci_t *xhci = container_of(pipe->pipe.cntl, usb_xhci_t, usb);
    uint32_t trt = datalen == 0 ? 0 : (dir ? 3 : 2);
    uint32_t status_dir = datalen == 0 ? 1 : !dir;

    xhci_trb_queue(&pipe->reqs, cmd,
                   xhci_trb_status(USB_CONTROL_SETUP_SIZE, pipe->interrupter),
                   (TR_SETUP << TRB_TYPE_SHIFT) | TRB_TR_IDT | (trt << 16));

    if (datalen && data) {
        xhci_trb_queue_split(&pipe->reqs, data, datalen,
                             (TR_DATA << TRB_TYPE_SHIFT) |
                                 (dir ? TRB_TR_DIR : 0),
                             pipe->interrupter, false);
    }

    xhci_trb_queue(&pipe->reqs, NULL, xhci_trb_status(0, pipe->interrupter),
                   (TR_STATUS << TRB_TYPE_SHIFT) | TRB_TR_IOC |
                       (status_dir ? TRB_TR_DIR : 0));
    xhci_doorbell(xhci, pipe->slotid, pipe->epid);
}

static void xhci_xfer_normal(struct xhci_pipe *pipe, void *data, int datalen) {
    usb_xhci_t *xhci = container_of(pipe->pipe.cntl, usb_xhci_t, usb);

    xhci_trb_queue_split(&pipe->reqs, data, datalen,
                         (TR_NORMAL << TRB_TYPE_SHIFT) | TRB_TR_IOC,
                         pipe->interrupter, true);
    xhci_doorbell(xhci, pipe->slotid, pipe->epid);
}

int xhci_send_pipe(usb_pipe_t *p, int dir, const void *cmd, void *data,
                   int datalen, uint64_t timeout_ns) {
    struct xhci_pipe *pipe = container_of(p, struct xhci_pipe, pipe);
    usb_xhci_t *xhci = container_of(p->cntl, usb_xhci_t, usb);
    int timeout_ms = timeout_ns != (uint64_t)-1 ? (int)(timeout_ns / 1000000ULL)
                                                : usb_xfer_time(p, datalen);

    if (data && datalen > 0)
        dma_sync_cpu_to_device(data, datalen);

    if (cmd)
        xhci_xfer_setup(pipe, dir, (void *)cmd, data, datalen);
    else
        xhci_xfer_normal(pipe, data, datalen);

    int cc = xhci_event_wait(xhci, &pipe->reqs, timeout_ms);
    if (cc != CC_SUCCESS && cc != CC_SHORT_PACKET)
        return -1;

    pipe->transfer_count++;

    if (dir && data) {
        uint32_t residue = pipe->reqs.evt.status & 0x00ffffff;
        int actual = datalen - residue;
        if (actual > 0)
            dma_sync_device_to_cpu(data, actual);
    }

    return 0;
}

int xhci_send_intr_pipe(usb_pipe_t *p, void *buf, int len, intr_xfer_cb cb,
                        void *user_data) {
    struct xhci_pipe *pipe = container_of(p, struct xhci_pipe, pipe);

    pipe->intr_xfer = cb;
    pipe->intr_xfer_data = user_data;
    xhci_xfer_normal(pipe, buf, len);
    return 0;
}

static void xhci_irq_handler(uint64_t irq_num, void *data,
                             struct pt_regs *regs) {
    (void)irq_num;
    (void)regs;

    struct xhci_event_ring *intr = data;
    uint32_t iman = readl(&intr->ir->iman);

    writel(&intr->ir->iman, iman | XHCI_IMAN_IP | XHCI_IMAN_IE);
    intr->pending = true;

    if (intr->xhci->event_task)
        task_unblock(intr->xhci->event_task, EOK);
}

static void xhci_event_thread(uint64_t arg) {
    usb_xhci_t *xhci = (usb_xhci_t *)arg;

    while (xhci->running) {
        xhci_process_events(xhci);
        task_block(current_task, TASK_BLOCKING, (int64_t)XHCI_EVENT_POLL_NS,
                   "xhci_event");
    }
}

static uint32_t xhci_choose_interrupters(usb_xhci_t *xhci) {
#if defined(__x86_64__)
    uint32_t desired =
        MIN(MAX_IO_CPU_NUM, MIN((uint32_t)cpu_count, xhci->max_intrs));
    return desired ? desired : 1;
#else
    return 1;
#endif
}

static void xhci_setup_irqs(usb_xhci_t *xhci) {
    // #if defined(__x86_64__)
    //     for (uint32_t i = 0; i < xhci->intr_count; i++) {
    //         struct msi_desc_t desc;
    //         int vector = irq_allocate_irqnum();

    //         memset(&desc, 0, sizeof(desc));
    //         desc.irq_num = (uint16_t)vector;
    //         desc.processor = cpuid_to_lapicid[i % cpu_count];
    //         desc.edge_trigger = 1;
    //         desc.assert = 0;
    //         desc.pci_dev = xhci->pci_dev;
    //         desc.msi_index = i;
    //         desc.pci.msi_attribute.is_msix = 1;
    //         desc.pci.msi_attribute.can_mask = 1;
    //         desc.pci.msi_attribute.is_64 = 1;

    //         if (pci_enable_msi(&desc) != 0)
    //             break;

    //         if (!desc.pci.msi_attribute.is_msix && i > 0)
    //             break;

    //         xhci->intrs[i].msi = desc;
    //         xhci->intrs[i].irq_vector = vector;
    //         irq_regist_irq((uint64_t)vector, xhci_irq_handler, 0,
    //         &xhci->intrs[i],
    //                        &apic_controller, "xhci-msix", IRQ_FLAGS_MSIX);

    //         if (!desc.pci.msi_attribute.is_msix)
    //             break;
    //     }
    // #else
    (void)xhci;
    // #endif
}

static int xhci_alloc_runtime_state(usb_xhci_t *xhci) {
    xhci->devs =
        alloc_frames_bytes_dma32(sizeof(*xhci->devs) * (xhci->slots + 1));
    if (!xhci->devs)
        return -ENOMEM;
    memset(xhci->devs, 0, sizeof(*xhci->devs) * (xhci->slots + 1));

    if (xhci_alloc_ring(&xhci->cmds) != 0)
        return -ENOMEM;

    xhci->intr_count = xhci_choose_interrupters(xhci);
    xhci->intrs = calloc(xhci->intr_count, sizeof(*xhci->intrs));
    if (!xhci->intrs)
        return -ENOMEM;

    for (uint32_t i = 0; i < xhci->intr_count; i++) {
        xhci->intrs[i].xhci = xhci;
        xhci->intrs[i].id = i;
        xhci->intrs[i].ir = xhci_ir_ptr(xhci, i);
        xhci->intrs[i].eseg =
            alloc_frames_bytes_dma32(sizeof(*xhci->intrs[i].eseg));
        if (!xhci->intrs[i].eseg || xhci_alloc_ring(&xhci->intrs[i].ring) != 0)
            return -ENOMEM;
        memset(xhci->intrs[i].eseg, 0, sizeof(*xhci->intrs[i].eseg));
    }

    xhci->pipes = calloc(xhci->slots + 1, sizeof(*xhci->pipes));
    if (!xhci->pipes)
        return -ENOMEM;

    for (uint32_t slot = 0; slot <= xhci->slots; slot++) {
        xhci->pipes[slot] = calloc(32, sizeof(*xhci->pipes[slot]));
        if (!xhci->pipes[slot])
            return -ENOMEM;
    }

    return 0;
}

static void xhci_program_interrupters(usb_xhci_t *xhci) {
    for (uint32_t i = 0; i < xhci->intr_count; i++) {
        struct xhci_event_ring *intr = &xhci->intrs[i];
        uint64_t ring_phys = xhci_virt_to_phys(intr->ring.trbs);
        uint64_t erst_phys = xhci_virt_to_phys(intr->eseg);

        intr->eseg->ptr_low = (uint32_t)ring_phys;
        intr->eseg->ptr_high = ring_phys >> 32;
        intr->eseg->size = XHCI_RING_ITEMS;
        dma_sync_cpu_to_device(intr->eseg, sizeof(*intr->eseg));

        writel(&intr->ir->erstsz, 1);
        writel(&intr->ir->erstba_low, (uint32_t)erst_phys);
        writel(&intr->ir->erstba_high, erst_phys >> 32);
        writel(&intr->ir->erdp_low, (uint32_t)(ring_phys & ~0xfU) | (1 << 3));
        writel(&intr->ir->erdp_high, ring_phys >> 32);
        writel(&intr->ir->imod, 0);
        writel(&intr->ir->iman, intr->irq_vector ? XHCI_IMAN_IE : 0);
    }
}

static int xhci_setup_scratchpad(usb_xhci_t *xhci) {
    uint32_t spb = xhci_max_scratchpad(readl(&xhci->caps->hcsparams2));
    if (!spb)
        return 0;

    uint64_t *spba = alloc_frames_bytes_dma32(sizeof(*spba) * spb);
    void *pad = alloc_frames_bytes_dma32(DEFAULT_PAGE_SIZE * spb);
    if (!spba || !pad)
        return -ENOMEM;

    for (uint32_t i = 0; i < spb; i++) {
        spba[i] = xhci_virt_to_phys((uint8_t *)pad + i * DEFAULT_PAGE_SIZE);
    }
    dma_sync_cpu_to_device(spba, sizeof(*spba) * spb);

    uint64_t spbap = xhci_virt_to_phys(spba);
    xhci->devs[0].ptr_low = (uint32_t)spbap;
    xhci->devs[0].ptr_high = spbap >> 32;
    dma_sync_cpu_to_device(&xhci->devs[0], sizeof(xhci->devs[0]));
    return 0;
}

static void xhci_power_ports(usb_xhci_t *xhci) {
    for (uint32_t port = 0; port < xhci->ports; port++) {
        uint32_t portsc = readl(&xhci->pr[port].portsc);
        if (!(portsc & XHCI_PORTSC_PP))
            writel(&xhci->pr[port].portsc, portsc | XHCI_PORTSC_PP);
    }
    delay(20);
}

static int xhci_start_controller(usb_xhci_t *xhci) {
    uint32_t reg;

    if (xhci_alloc_runtime_state(xhci) != 0)
        return -ENOMEM;

    reg = readl(&xhci->op->usbcmd);
    if (reg & XHCI_CMD_RS) {
        writel(&xhci->op->usbcmd, reg & ~XHCI_CMD_RS);
        if (wait_bit(&xhci->op->usbsts, XHCI_STS_HCH, XHCI_STS_HCH, 3000) != 0)
            return -EIO;
    }

    writel(&xhci->op->usbcmd, XHCI_CMD_HCRST);
    if (wait_bit(&xhci->op->usbcmd, XHCI_CMD_HCRST, 0, 3000) != 0)
        return -EIO;
    if (wait_bit(&xhci->op->usbsts, XHCI_STS_CNR, 0, 3000) != 0)
        return -EIO;

    writel(&xhci->op->config, xhci->slots);

    uint64_t dcbaap = xhci_virt_to_phys(xhci->devs);
    writel(&xhci->op->dcbaap_low, (uint32_t)dcbaap);
    writel(&xhci->op->dcbaap_high, dcbaap >> 32);

    uint64_t crcr = xhci_virt_to_phys(xhci->cmds.trbs);
    writel(&xhci->op->crcr_low, (uint32_t)(crcr & ~0x3fU) | 1);
    writel(&xhci->op->crcr_high, crcr >> 32);
    xhci->cmds.cs = 1;

    xhci_setup_irqs(xhci);
    xhci_program_interrupters(xhci);
    if (xhci_setup_scratchpad(xhci) != 0)
        return -ENOMEM;

    reg = readl(&xhci->op->usbcmd);
    reg |= XHCI_CMD_INTE | XHCI_CMD_RS;
    writel(&xhci->op->usbcmd, reg);

    if (wait_bit(&xhci->op->usbsts, XHCI_STS_HCH, 0, 1000) != 0)
        return -EIO;

    delay(10);
    xhci_power_ports(xhci);

    xhci->running = true;
    xhci->event_task = task_create("xhci_event", xhci_event_thread,
                                   (uint64_t)xhci, KTHREAD_PRIORITY);

    usb_hub_t *hub = calloc(1, sizeof(*hub));
    if (!hub)
        return -ENOMEM;
    hub->cntl = &xhci->usb;
    hub->portcount = xhci->ports;
    hub->op = &xhci_hub_ops;

    usb_register_controller(&xhci->usb, hub);
    return 0;
}

static usb_xhci_t *xhci_controller_setup(void *baseaddr) {
    usb_xhci_t *xhci = calloc(1, sizeof(*xhci));
    if (!xhci)
        return NULL;

    xhci->usb.mmio = baseaddr;
    xhci->usb.type = USB_TYPE_XHCI;
    xhci->usb.flags = USB_CNTL_FLAG_NATIVE_ADDR;
    spin_init(&xhci->event_lock);

    xhci->caps = baseaddr;
    xhci->op = (void *)((uint8_t *)baseaddr + readb(&xhci->caps->caplength));
    xhci->pr = (void *)((uint8_t *)xhci->op + 0x400);
    xhci->db = (void *)((uint8_t *)baseaddr + readl(&xhci->caps->dboff));

    uint32_t hcs1 = readl(&xhci->caps->hcsparams1);
    uint32_t hcc = readl(&xhci->caps->hccparams);

    xhci->ports =
        (hcs1 >> XHCI_HCS1_MAX_PORTS_SHIFT) & XHCI_HCS1_MAX_PORTS_MASK;
    xhci->slots = hcs1 & XHCI_HCS1_MAX_SLOTS_MASK;
    xhci->max_intrs =
        (hcs1 >> XHCI_HCS1_MAX_INTRS_SHIFT) & XHCI_HCS1_MAX_INTRS_MASK;
    xhci->xcap = ((hcc >> 16) & 0xffff) << 2;
    xhci->context64 = (hcc & 0x04) ? 1 : 0;

    if (!(readl(&xhci->op->pagesize) & 1U)) {
        printk("xhci: controller does not support 4K pages\n");
        free(xhci);
        return NULL;
    }

    if (xhci->xcap) {
        uint8_t *addr = (uint8_t *)baseaddr + xhci->xcap;

        for (;;) {
            struct xhci_xcap *xcap = (void *)addr;
            uint32_t cap = readl(&xcap->cap);
            uint32_t off = (cap >> 8) & 0xff;

            if ((cap & 0xff) == 0x02) {
                uint32_t name = readl(&xcap->data[0]);
                uint32_t ports = readl(&xcap->data[1]);
                uint8_t major = (cap >> 24) & 0xff;
                uint8_t count = (ports >> 8) & 0xff;
                uint8_t start = ports & 0xff;

                if (name == 0x20425355) {
                    if (major == 2) {
                        xhci->usb2.start = start;
                        xhci->usb2.count = count;
                    } else if (major == 3) {
                        xhci->usb3.start = start;
                        xhci->usb3.count = count;
                    }
                }
            }

            if (!off)
                break;
            addr += off << 2;
        }
    }

    return xhci;
}

static void xhci_free_controller(usb_xhci_t *xhci) {
    if (!xhci)
        return;

    xhci->running = false;
    if (xhci->event_task)
        task_unblock(xhci->event_task, EOK);

    if (xhci->intrs) {
        for (uint32_t i = 0; i < xhci->intr_count; i++) {
            xhci_free_ring(&xhci->intrs[i].ring);
            if (xhci->intrs[i].eseg)
                free_frames_bytes_dma32(xhci->intrs[i].eseg,
                                        sizeof(*xhci->intrs[i].eseg));
        }
        free(xhci->intrs);
    }

    if (xhci->pipes) {
        for (uint32_t slot = 0; slot <= xhci->slots; slot++)
            free(xhci->pipes[slot]);
        free(xhci->pipes);
    }

    xhci_free_ring(&xhci->cmds);
    if (xhci->devs)
        free_frames_bytes_dma32(xhci->devs,
                                sizeof(*xhci->devs) * (xhci->slots + 1));
    free(xhci);
}

int xhci_hcd_driver_probe(pci_device_t *pci_dev, uint32_t vendor_device_id) {
    (void)vendor_device_id;

    uint64_t mmio_base = 0;
    uint64_t mmio_size = 0;

    for (int i = 0; i < 6; i++) {
        if (!pci_dev->bars[i].size || !pci_dev->bars[i].mmio)
            continue;
        mmio_base = pci_dev->bars[i].address;
        mmio_size = pci_dev->bars[i].size;
        break;
    }

    if (!mmio_base) {
        printk("xhci: no MMIO BAR found\n");
        return -1;
    }

    void *mmio_vaddr = (void *)phys_to_virt(mmio_base);
    map_page_range(get_current_page_dir(false), (uint64_t)mmio_vaddr, mmio_base,
                   mmio_size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);

    usb_xhci_t *xhci = xhci_controller_setup(mmio_vaddr);
    if (!xhci)
        return -ENOMEM;

    xhci->usb.pci = pci_dev;
    xhci->pci_dev = pci_dev;

    if (pci_dev->vendor_id == 0x1106 && pci_dev->device_id == 0x3483 &&
        pci_dev->revision_id < 0x04) {
        xhci->quirks |= XHCI_QUIRK_VL805_OLD_REV;
    }

    if (xhci_start_controller(xhci) != 0) {
        xhci_free_controller(xhci);
        return -EIO;
    }

    pci_dev->desc = xhci;
    return 0;
}

void xhci_hcd_driver_remove(pci_device_t *dev) {
    usb_xhci_t *xhci = dev ? dev->desc : NULL;
    if (!xhci)
        return;

    usb_unregister_controller(&xhci->usb);
    xhci_free_controller(xhci);
    dev->desc = NULL;
}

void xhci_hcd_driver_shutdown(pci_device_t *dev) {
    xhci_hcd_driver_remove(dev);
}

pci_driver_t xhci_hcd_driver = {
    .name = "xhci_hcd",
    .class_id = 0x000C0330,
    .vendor_device_id = 0x00000000,
    .probe = xhci_hcd_driver_probe,
    .remove = xhci_hcd_driver_remove,
    .shutdown = xhci_hcd_driver_shutdown,
    .flags = 0,
};

__attribute__((visibility("default"))) int dlmain() {
    regist_pci_driver(&xhci_hcd_driver);
    return 0;
}
