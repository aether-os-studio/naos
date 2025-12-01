// Code for handling XHCI "Super speed" USB controllers.
//
// Copyright (C) 2013  Gerd Hoffmann <kraxel@redhat.com>
// Copyright (C) 2014  Kevin O'Connor <kevin@koconnor.net>
//
// This file may be distributed under the terms of the GNU LGPLv3 license.

#include "xhci-hcd.h"
#include <libs/aether/pci.h>
#include <libs/aether/irq.h>
#include <libs/aether/task.h>

// --------------------------------------------------------------
// configuration

#define XHCI_RING_ITEMS 64
#define XHCI_RING_SIZE (XHCI_RING_ITEMS * sizeof(struct xhci_trb))

/*
 *  xhci_ring structs are allocated with XHCI_RING_SIZE alignment,
 *  then we can get it from a trb pointer (provided by evt ring).
 */
#define XHCI_RING(_trb)                                                        \
    ((struct xhci_ring *)((uint64_t)(_trb) & ~(XHCI_RING_SIZE - 1)))

// --------------------------------------------------------------
// bit definitions

#define XHCI_CMD_RS (1 << 0)
#define XHCI_CMD_HCRST (1 << 1)
#define XHCI_CMD_INTE (1 << 2)
#define XHCI_CMD_HSEE (1 << 3)
#define XHCI_CMD_LHCRST (1 << 7)
#define XHCI_CMD_CSS (1 << 8)
#define XHCI_CMD_CRS (1 << 9)
#define XHCI_CMD_EWE (1 << 10)
#define XHCI_CMD_EU3S (1 << 11)

#define XHCI_STS_HCH (1 << 0)
#define XHCI_STS_HSE (1 << 2)
#define XHCI_STS_EINT (1 << 3)
#define XHCI_STS_PCD (1 << 4)
#define XHCI_STS_SSS (1 << 8)
#define XHCI_STS_RSS (1 << 9)
#define XHCI_STS_SRE (1 << 10)
#define XHCI_STS_CNR (1 << 11)
#define XHCI_STS_HCE (1 << 12)

#define XHCI_PORTSC_CCS (1 << 0)
#define XHCI_PORTSC_PED (1 << 1)
#define XHCI_PORTSC_OCA (1 << 3)
#define XHCI_PORTSC_PR (1 << 4)
#define XHCI_PORTSC_PLS_SHIFT 5
#define XHCI_PORTSC_PLS_MASK 0xf
#define XHCI_PORTSC_PP (1 << 9)
#define XHCI_PORTSC_SPEED_SHIFT 10
#define XHCI_PORTSC_SPEED_MASK 0xf
#define XHCI_PORTSC_SPEED_FULL (1 << 10)
#define XHCI_PORTSC_SPEED_LOW (2 << 10)
#define XHCI_PORTSC_SPEED_HIGH (3 << 10)
#define XHCI_PORTSC_SPEED_SUPER (4 << 10)
#define XHCI_PORTSC_PIC_SHIFT 14
#define XHCI_PORTSC_PIC_MASK 0x3
#define XHCI_PORTSC_LWS (1 << 16)
#define XHCI_PORTSC_CSC (1 << 17)
#define XHCI_PORTSC_PEC (1 << 18)
#define XHCI_PORTSC_WRC (1 << 19)
#define XHCI_PORTSC_OCC (1 << 20)
#define XHCI_PORTSC_PRC (1 << 21)
#define XHCI_PORTSC_PLC (1 << 22)
#define XHCI_PORTSC_CEC (1 << 23)
#define XHCI_PORTSC_CAS (1 << 24)
#define XHCI_PORTSC_WCE (1 << 25)
#define XHCI_PORTSC_WDE (1 << 26)
#define XHCI_PORTSC_WOE (1 << 27)
#define XHCI_PORTSC_DR (1 << 30)
#define XHCI_PORTSC_WPR (1 << 31)

#define TRB_C (1 << 0)
#define TRB_TYPE_SHIFT 10
#define TRB_TYPE_MASK 0x3f
#define TRB_TYPE(t) (((t) >> TRB_TYPE_SHIFT) & TRB_TYPE_MASK)

#define TRB_EV_ED (1 << 2)

#define TRB_TR_ENT (1 << 1)
#define TRB_TR_ISP (1 << 2)
#define TRB_TR_NS (1 << 3)
#define TRB_TR_CH (1 << 4)
#define TRB_TR_IOC (1 << 5)
#define TRB_TR_IDT (1 << 6)
#define TRB_TR_TBC_SHIFT 7
#define TRB_TR_TBC_MASK 0x3
#define TRB_TR_BEI (1 << 9)
#define TRB_TR_TLBPC_SHIFT 16
#define TRB_TR_TLBPC_MASK 0xf
#define TRB_TR_FRAMEID_SHIFT 20
#define TRB_TR_FRAMEID_MASK 0x7ff
#define TRB_TR_SIA (1 << 31)

#define TRB_TR_DIR (1 << 16)

#define TRB_CR_SLOTID_SHIFT 24
#define TRB_CR_SLOTID_MASK 0xff
#define TRB_CR_EPID_SHIFT 16
#define TRB_CR_EPID_MASK 0x1f

#define TRB_CR_BSR (1 << 9)
#define TRB_CR_DC (1 << 9)

#define TRB_LK_TC (1 << 1)

#define TRB_INTR_SHIFT 22
#define TRB_INTR_MASK 0x3ff
#define TRB_INTR(t) (((t).status >> TRB_INTR_SHIFT) & TRB_INTR_MASK)

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
    PLS_U1 = 1,
    PLS_U2 = 2,
    PLS_U3 = 3,
    PLS_DISABLED = 4,
    PLS_RX_DETECT = 5,
    PLS_INACTIVE = 6,
    PLS_POLLING = 7,
    PLS_RECOVERY = 8,
    PLS_HOT_RESET = 9,
    PLS_COMPILANCE_MODE = 10,
    PLS_TEST_MODE = 11,
    PLS_RESUME = 15,
};

#define xhci_get_field(data, field) (((data) >> field##_SHIFT) & field##_MASK)

// --------------------------------------------------------------
// state structs

struct xhci_ring {
    spinlock_t lock;
    struct xhci_trb *ring;
    uint32_t nidx;
    uint32_t eidx;
    uint32_t cs;
    struct xhci_trb evt;
};

struct xhci_portmap {
    uint8_t start;
    uint8_t count;
};

struct xhci_pipe {
    struct xhci_ring reqs;

    struct usb_pipe pipe;
    uint32_t slotid;
    uint32_t epid;

    int transfer_count;

    intr_xfer_cb intr_xfer;
    void *intr_xfer_data;
};

struct usb_xhci_s {
    struct usb_s usb;

    pci_device_t *pci_dev;

    /* devinfo */
    uint32_t xcap;
    uint32_t ports;
    uint32_t slots;
    uint8_t context64;
    struct xhci_portmap usb2;
    struct xhci_portmap usb3;

    /* xhci registers */
    struct xhci_caps *caps;
    struct xhci_op *op;
    struct xhci_pr *pr;
    struct xhci_ir *ir;
    struct xhci_db *db;

    /* xhci data structures */
    struct xhci_devlist *devs;
    struct xhci_ring *cmds;
    struct xhci_ring *evts;
    struct xhci_er_seg *eseg;

    struct xhci_pipe ***pipes;

#define XHCI_QUIRK_VL805_OLD_REV (1UL << 0)
    uint64_t quirks;
};

// --------------------------------------------------------------
// tables

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
    uint64_t ns = ms * 1000000ULL;
    uint64_t timeout = nanoTime() + ns;
    while (nanoTime() < timeout) {
        arch_pause();
    }
}

static int wait_bit(volatile uint32_t *reg, uint32_t mask, uint32_t value,
                    uint32_t timeout) {
    uint64_t timeout_ns = nanoTime() + (uint64_t)timeout * 1000000ULL;
    while ((readl((const void *)reg) & mask) != value) {
        if (nanoTime() > timeout_ns) {
            printk("wait_bit timeout: reg=%p mask=0x%x expected=0x%x "
                   "actual=0x%x\n",
                   reg, mask, value, readl((const void *)reg) & mask);
            return -1;
        }
        arch_pause();
    }
    return 0;
}

// Root hub

#define XHCI_TIME_POSTPOWER 20

// Check if device attached to port
static void xhci_print_port_state(int loglevel, const char *prefix,
                                  uint32_t port, uint32_t portsc) {
    uint32_t pls = xhci_get_field(portsc, XHCI_PORTSC_PLS);
    uint32_t speed = xhci_get_field(portsc, XHCI_PORTSC_SPEED);

    printk("%s port #%d: 0x%08x,%s%s pls %d, speed %d [%s]\n", prefix, port + 1,
           portsc, (portsc & XHCI_PORTSC_PP) ? " powered," : "",
           (portsc & XHCI_PORTSC_PED) ? " enabled," : "", pls, speed,
           speed_name[speed]);
}

static int xhci_hub_detect(struct usbhub_s *hub, uint32_t port) {
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    uint32_t portsc = readl(&xhci->pr[port].portsc);
    return (portsc & XHCI_PORTSC_CCS) ? 1 : 0;
}

// Reset device on port
static int xhci_hub_reset(struct usbhub_s *hub, uint32_t port) {
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    uint32_t portsc = readl(&xhci->pr[port].portsc);
    if (!(portsc & XHCI_PORTSC_CCS))
        return -1;

    switch (xhci_get_field(portsc, XHCI_PORTSC_PLS)) {
    case PLS_U0:
        break;
    case PLS_POLLING:
        writel(&xhci->pr[port].portsc, portsc | XHCI_PORTSC_PR);
        break;
    default:
        printk("XHCI: Unknown PLS %d\n",
               xhci_get_field(portsc, XHCI_PORTSC_PLS));
        return -1;
    }

    uint64_t timeout = nanoTime() + 2000000000ULL; // 2秒超时
    for (;;) {
        if (nanoTime() > timeout) {
            printk("XHCI: Port %d reset timeout\n", port);
            return -1;
        }

        portsc = readl(&xhci->pr[port].portsc);
        if (!(portsc & XHCI_PORTSC_CCS))
            return -1;
        if (portsc & XHCI_PORTSC_PED)
            break;
        arch_pause();
    }

    delay(10);

    int rc = speed_from_xhci[xhci_get_field(portsc, XHCI_PORTSC_SPEED)];
    xhci_print_port_state(1, "XHCI", port, portsc);
    return rc;
}

static int xhci_hub_portmap(struct usbhub_s *hub, uint32_t vport) {
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    uint32_t pport = vport + 1;

    if (vport + 1 >= xhci->usb3.start &&
        vport + 1 < xhci->usb3.start + xhci->usb3.count)
        pport = vport + 2 - xhci->usb3.start;

    if (vport + 1 >= xhci->usb2.start &&
        vport + 1 < xhci->usb2.start + xhci->usb2.count)
        pport = vport + 2 - xhci->usb2.start;

    return pport;
}

static void xhci_hub_disconnect(struct usbhub_s *hub, uint32_t port) {
    // XXX - should turn the port power off.
}

static struct usbhub_op_s xhci_hub_ops = {
    .detect = xhci_hub_detect,
    .reset = xhci_hub_reset,
    .portmap = xhci_hub_portmap,
    .disconnect = xhci_hub_disconnect,

    .realloc_pipe = xhci_realloc_pipe,
    .send_pipe = xhci_send_pipe,
    .send_intr_pipe = xhci_send_intr_pipe,
};

// Find any devices connected to the root hub.
static int xhci_check_ports(struct usb_xhci_s *xhci) {
    // Wait for port power to stabilize.
    delay(XHCI_TIME_POSTPOWER);

    struct usbhub_s *hub = malloc(sizeof(struct usbhub_s));
    memset(hub, 0, sizeof(struct usbhub_s));
    hub->cntl = &xhci->usb;
    hub->portcount = xhci->ports;
    hub->op = &xhci_hub_ops;
    usb_enumerate(hub);
    int count = hub->devcount;

    return count;
}

/****************************************************************
 * Setup
 ****************************************************************/

static void xhci_free_pipes(struct usb_xhci_s *xhci) {
    // XXX - should walk list of pipes and free unused pipes.
}

static void xhci_event_handler(uint64_t arg);

static void configure_xhci(void *data) {
    struct usb_xhci_s *xhci = data;
    uint32_t reg;

    // 分配内存
    xhci->devs =
        alloc_frames_bytes_dma32(sizeof(*xhci->devs) * (xhci->slots + 1));
    xhci->eseg = alloc_frames_bytes_dma32(sizeof(*xhci->eseg));
    xhci->cmds = alloc_frames_bytes_dma32(sizeof(*xhci->cmds));
    xhci->evts = alloc_frames_bytes_dma32(sizeof(*xhci->evts));

    if (!xhci->devs || !xhci->cmds || !xhci->evts || !xhci->eseg) {
        goto fail;
    }

    memset(xhci->devs, 0, sizeof(*xhci->devs) * (xhci->slots + 1));
    memset(xhci->cmds, 0, sizeof(*xhci->cmds));
    memset(xhci->evts, 0, sizeof(*xhci->evts));
    memset(xhci->eseg, 0, sizeof(*xhci->eseg));

    dma_sync_cpu_to_device(xhci->devs, sizeof(*xhci->devs) * (xhci->slots + 1));
    dma_sync_cpu_to_device(xhci->cmds, sizeof(*xhci->cmds));
    dma_sync_cpu_to_device(xhci->evts, sizeof(*xhci->evts));

    xhci->cmds->ring = alloc_frames_bytes_dma32(XHCI_RING_SIZE * 2);
    memset(xhci->cmds->ring, 0, XHCI_RING_SIZE * 2);
    dma_sync_cpu_to_device(xhci->cmds->ring, XHCI_RING_SIZE * 2);
    xhci->evts->ring = alloc_frames_bytes_dma32(XHCI_RING_SIZE * 2);
    memset(xhci->evts->ring, 0, XHCI_RING_SIZE * 2);
    dma_sync_cpu_to_device(xhci->evts->ring, XHCI_RING_SIZE * 2);

    xhci->pipes = malloc(sizeof(struct xhci_pipe **) * (xhci->slots + 1));
    memset(xhci->pipes, 0, sizeof(struct xhci_pipe **) * (xhci->slots + 1));
    for (uint32_t slot = 0; slot < xhci->slots; slot++) {
        xhci->pipes[slot] = malloc(sizeof(struct xhci_pipe *) * 32);
        memset(xhci->pipes[slot], 0, sizeof(struct xhci_pipe *) * 32);
    }

    // 停止控制器
    reg = readl(&xhci->op->usbcmd);
    if (reg & XHCI_CMD_RS) {
        reg &= ~XHCI_CMD_RS;
        writel(&xhci->op->usbcmd, reg);
        if (wait_bit(&xhci->op->usbsts, XHCI_STS_HCH, XHCI_STS_HCH, 3000) != 0)
            goto fail;
    }

    // 重置控制器
    writel(&xhci->op->usbcmd, XHCI_CMD_HCRST);
    if (wait_bit(&xhci->op->usbcmd, XHCI_CMD_HCRST, 0, 3000) != 0)
        goto fail;
    if (wait_bit(&xhci->op->usbsts, XHCI_STS_CNR, 0, 3000) != 0)
        goto fail;

    // 配置槽位
    writel(&xhci->op->config, xhci->slots);

    // 设置DCBAAP
    uint64_t dcbaap =
        translate_address(get_current_page_dir(false), (uint64_t)xhci->devs);
    writel(&xhci->op->dcbaap_low, dcbaap);
    writel(&xhci->op->dcbaap_high, dcbaap >> 32);

    uint64_t crcr = translate_address(get_current_page_dir(false),
                                      (uint64_t)&xhci->cmds->ring[0]);
    writel(&xhci->op->crcr_low, (crcr & ~0x3F) | 1); // 保留RCS=1
    writel(&xhci->op->crcr_high, crcr >> 32);
    xhci->cmds->cs = 1;

    // 事件环
    uint64_t evts = translate_address(get_current_page_dir(false),
                                      (uint64_t)&xhci->evts->ring[0]);
    xhci->eseg->ptr_low = evts;
    xhci->eseg->ptr_high = evts >> 32;
    xhci->eseg->size = XHCI_RING_ITEMS;

    dma_sync_cpu_to_device(xhci->eseg, sizeof(*xhci->eseg));

    writel(&xhci->ir->erstsz, 1);
    writel(&xhci->ir->erdp_low, evts | (1 << 3));
    writel(&xhci->ir->erdp_high, evts >> 32);

    uint64_t erstba =
        translate_address(get_current_page_dir(false), (uint64_t)xhci->eseg);
    writel(&xhci->ir->erstba_low, erstba);
    writel(&xhci->ir->erstba_high, erstba >> 32);
    xhci->evts->cs = 1;

    // Scratchpad buffers
    reg = readl(&xhci->caps->hcsparams2);
    uint32_t spb = (reg >> 21 & 0x1f) << 5 | reg >> 27;
    if (spb) {
        uint64_t *spba = alloc_frames_bytes_dma32(sizeof(*spba) * spb);
        void *pad = alloc_frames_bytes_dma32(DEFAULT_PAGE_SIZE * spb);
        if (!spba || !pad) {
            free_frames_bytes_dma32(spba, sizeof(*spba) * spb);
            free_frames_bytes_dma32(pad, DEFAULT_PAGE_SIZE * spb);
            goto fail;
        }

        for (int i = 0; i < spb; i++) {
            spba[i] =
                translate_address(get_current_page_dir(false),
                                  (uint64_t)pad + (i * DEFAULT_PAGE_SIZE));
        }

        dma_sync_cpu_to_device(spba, sizeof(*spba) * spb);

        uint64_t spbap =
            translate_address(get_current_page_dir(false), (uint64_t)spba);
        xhci->devs[0].ptr_low = spbap;
        xhci->devs[0].ptr_high = spbap >> 32;

        dma_sync_cpu_to_device(&xhci->devs[0], sizeof(xhci->devs[0]));
    }

    // 启动控制器
    reg = readl(&xhci->op->usbcmd);
    reg |= XHCI_CMD_RS;
    writel(&xhci->op->usbcmd, reg);

    if (wait_bit(&xhci->op->usbsts, XHCI_STS_HCH, 0, 1000) != 0) {
        printk("xhci: Controller failed to start\n");
        goto fail;
    }

    delay(10);

    writel(&xhci->ir->imod, 0);
    writel(&xhci->ir->iman, 0);

    reg = readl(&xhci->op->usbcmd);
    reg &= ~XHCI_CMD_INTE;
    writel(&xhci->op->usbcmd, reg);

    if (xhci->pci_dev->vendor_id == 0x1106 ||
        xhci->pci_dev->device_id == 0x3483) {
        printk("Applying VL805 Quirks\n");
        if (xhci->pci_dev->revision_id < 0x04) {
            xhci->quirks |= XHCI_QUIRK_VL805_OLD_REV;
        }
    }

    task_create("xhci_event_handler", xhci_event_handler, (uint64_t)xhci,
                KTHREAD_PRIORITY);

    // 查找设备
    int count = xhci_check_ports(xhci);
    return;

fail:
    free_frames_bytes_dma32(xhci->devs,
                            sizeof(*xhci->devs) * (xhci->slots + 1));
    free_frames_bytes_dma32(xhci->eseg, sizeof(*xhci->eseg));
    free_frames_bytes_dma32(xhci->cmds, sizeof(*xhci->cmds));
    free_frames_bytes_dma32(xhci->evts, sizeof(*xhci->evts));
    free(xhci);
}

static struct usb_xhci_s *xhci_controller_setup(void *baseaddr) {
    struct usb_xhci_s *xhci = malloc(sizeof(*xhci));
    if (!xhci) {
        return NULL;
    }
    memset(xhci, 0, sizeof(*xhci));
    xhci->usb.mmio = baseaddr;
    xhci->caps = baseaddr;
    xhci->op = baseaddr + readb(&xhci->caps->caplength);
    xhci->pr = baseaddr + readb(&xhci->caps->caplength) + 0x400;
    xhci->db = baseaddr + readl(&xhci->caps->dboff);
    xhci->ir = baseaddr + readl(&xhci->caps->rtsoff) + 0x20;

    uint32_t hcs1 = readl(&xhci->caps->hcsparams1);
    uint32_t hcc = readl(&xhci->caps->hccparams);
    xhci->ports = (hcs1 >> 24) & 0xff;
    xhci->slots = hcs1 & 0xff;
    xhci->xcap = ((hcc >> 16) & 0xffff) << 2;
    xhci->context64 = (hcc & 0x04) ? 1 : 0;
    xhci->usb.type = USB_TYPE_XHCI;

    if (xhci->xcap) {
        uint32_t off;
        void *addr = baseaddr + xhci->xcap;
        do {
            struct xhci_xcap *xcap = addr;
            uint32_t ports, name, cap = readl(&xcap->cap);
            switch (cap & 0xff) {
            case 0x02:
                name = readl(&xcap->data[0]);
                ports = readl(&xcap->data[1]);
                uint8_t major = (cap >> 24) & 0xff;
                uint8_t minor = (cap >> 16) & 0xff;
                uint8_t count = (ports >> 8) & 0xff;
                uint8_t start = (ports >> 0) & 0xff;
                printk("XHCI protocol %c%c%c%c %x.%02x"
                       ", %d ports (offset %d), def %x\n",
                       (name >> 0) & 0xff, (name >> 8) & 0xff,
                       (name >> 16) & 0xff, (name >> 24) & 0xff, major, minor,
                       count, start, ports >> 16);
                if (name == 0x20425355) { /* "USB " */
                    if (major == 2) {
                        xhci->usb2.start = start;
                        xhci->usb2.count = count;
                    }
                    if (major == 3) {
                        xhci->usb3.start = start;
                        xhci->usb3.count = count;
                    }
                }
                break;
            default:
                printk("XHCI extcap 0x%x @ %p\n", cap & 0xff, addr);
                break;
            }
            off = (cap >> 8) & 0xff;
            addr += off << 2;
        } while (off > 0);
    }

    uint32_t pagesize = readl(&xhci->op->pagesize);
    if (DEFAULT_PAGE_SIZE != (pagesize << 12)) {
        printk("XHCI driver does not support page size code %d\n",
               pagesize << 12);
        free(xhci);
        return NULL;
    }

    return xhci;
}

// Signal the hardware to process events on a TRB ring
static void xhci_doorbell(struct usb_xhci_s *xhci, uint32_t slotid,
                          uint32_t value) {
    struct xhci_db *db = xhci->db;
    dma_mb();
    writel(&db[slotid].doorbell, value);
    dma_mb();
    readl(&db[slotid].doorbell);
    dma_mb();
}

static struct xhci_pipe *xhci_find_pipe(struct usb_xhci_s *xhci,
                                        uint32_t slotid, uint32_t epid) {
    if (slotid > xhci->slots || epid >= 32) {
        return NULL;
    }
    return xhci->pipes[slotid][epid];
}

static int xhci_cc_to_status(uint32_t completion_code) {
    switch (completion_code) {
    case 1: // SUCCESS
        return EVENT_SUCCESS;
    case 13: // SHORT_PACKET
        return EVENT_SHORT_PACKET;
    case 6: // STALL_ERROR
        return EVENT_STALL;
    case 3: // BABBLE_DETECTED_ERROR
        return EVENT_BABBLE;
    case 4: // USB_TRANSACTION_ERROR
    case 5: // TRB_ERROR
    default:
        return EVENT_ERROR;
    }
}

spinlock_t event_processing_lock = SPIN_INIT;

// Dequeue events on the XHCI command ring generated by the hardware
static void xhci_process_events(struct usb_xhci_s *xhci) {
    struct xhci_ring *evts = xhci->evts;
    int events_processed = 0;

    spin_lock_no_irqsave(&event_processing_lock);

    for (;;) {
        uint32_t nidx = evts->nidx;
        uint32_t cs = evts->cs;
        struct xhci_trb *etrb = evts->ring + nidx;

        dma_sync_device_to_cpu(etrb, sizeof(struct xhci_trb));

        uint32_t trb_c = !!(readl(&etrb->control) & TRB_C);
        if (trb_c != cs) {
            break; // 没有更多事件
        }

        uint32_t evt_type = TRB_TYPE(readl(&etrb->control));
        uint32_t evt_cc = (readl(&etrb->status) >> 24) & 0xff;

        switch (evt_type) {
        case ER_TRANSFER: {
            uint32_t slotid =
                xhci_get_field(readl(&etrb->control), TRB_CR_SLOTID);
            uint32_t epid = xhci_get_field(readl(&etrb->control), TRB_CR_EPID);

            struct xhci_pipe *pipe = xhci_find_pipe(xhci, slotid, epid);
            if (pipe) {
                struct xhci_ring *ring = &pipe->reqs;
                struct xhci_trb *rtrb_phys =
                    (struct xhci_trb *)(((uint64_t)readl(&etrb->ptr_high)
                                         << 32) |
                                        readl(&etrb->ptr_low));
                struct xhci_trb *ftrb_phys =
                    (struct xhci_trb *)translate_address(
                        get_current_page_dir(false), (uint64_t)ring->ring);
                uint32_t eidx = (uint32_t)(rtrb_phys - ftrb_phys) + 1;
                memcpy(&ring->evt, etrb, sizeof(*etrb));
                ring->eidx = eidx;

                if (pipe->pipe.eptype == USB_ENDPOINT_XFER_INT) {
                    if (pipe->intr_xfer) {
                        pipe->intr_xfer(xhci_cc_to_status(evt_cc),
                                        pipe->intr_xfer_data);
                    }
                }
            } else {
                printk(
                    "XHCI: Transfer event for unknown pipe (slot %d, ep %d)\n",
                    slotid, epid);
            }
            break;
        }
        case ER_COMMAND_COMPLETE: {
            struct xhci_ring *ring = xhci->cmds;
            struct xhci_trb *rtrb = (struct xhci_trb *)phys_to_virt(
                ((uint64_t)etrb->ptr_high << 32) | (etrb->ptr_low));
            uint32_t eidx = (uint32_t)(rtrb - ring->ring) + 1;
            memcpy(&ring->evt, etrb, sizeof(*etrb));
            ring->eidx = eidx;
            break;
        }
        case ER_PORT_STATUS_CHANGE: {
            uint32_t port = ((etrb->ptr_low >> 24) & 0xff) - 1;
            uint32_t portsc = readl(&xhci->pr[port].portsc);
            uint32_t pclear =
                (((portsc & ~(XHCI_PORTSC_PED | XHCI_PORTSC_PR)) &
                  ~(XHCI_PORTSC_PLS_MASK << XHCI_PORTSC_PLS_SHIFT)) |
                 (1 << XHCI_PORTSC_PLS_SHIFT));
            writel(&xhci->pr[port].portsc, pclear);
            xhci_print_port_state(3, __func__, port, portsc);
            break;
        }
        default:
            printk("%s: unknown event, type %d, cc %d\n", __func__, evt_type,
                   evt_cc);
            break;
        }

        nidx++;
        if (nidx >= XHCI_RING_ITEMS) {
            nidx = 0;
            cs = !cs;
            evts->cs = cs;
        }
        evts->nidx = nidx;
        events_processed++;
    }

    // 更新 ERDP
    if (events_processed > 0) {
        dma_sync_device_to_cpu(evts->ring, XHCI_RING_SIZE);

        struct xhci_ir *ir = xhci->ir;
        uint64_t erdp = translate_address(get_current_page_dir(false),
                                          (uint64_t)&evts->ring[evts->nidx]);

        writel(&ir->erdp_low, (erdp & ~0xF) | (1 << 3)); // EHB bit
        writel(&ir->erdp_high, erdp >> 32);

        // VL805 Workaround: 必须读回确认
        if (xhci->quirks & XHCI_QUIRK_VL805_OLD_REV) {
            uint32_t read_erdp_low = readl(&ir->erdp_low);
            uint32_t read_erdp_high = readl(&ir->erdp_high);

            uint64_t read_erdp =
                ((uint64_t)read_erdp_high << 32) | (read_erdp_low & ~0xF);
            if (erdp != read_erdp) {
                printk(
                    "The ERDP has been updated, but there doesn't seem to be "
                    "any changes\n");
            }

            writel(&ir->erdp_low, read_erdp);
            writel(&ir->erdp_high, read_erdp >> 32);

            // 额外写入一次 IMAN 来"踢"控制器
            writel(&ir->iman, 0x3);
        }
    }

    spin_unlock_no_irqstore(&event_processing_lock);
}

static void xhci_event_handler(uint64_t arg) {
    struct usb_xhci_s *xhci = (struct usb_xhci_s *)arg;
    while (1) {
        xhci_process_events(xhci);
        arch_yield();
    }
}

// Check if a ring has any pending TRBs
static bool xhci_ring_busy(struct xhci_ring *ring) {
    return (ring->eidx != ring->nidx);
}

// Wait for a ring to empty (all TRBs processed by hardware)
static int xhci_event_wait(struct usb_xhci_s *xhci, struct xhci_ring *ring,
                           uint32_t timeout) {
    uint64_t timeout_ns = nanoTime() + (uint64_t)timeout * 1000000ULL;
    for (;;) {
        xhci_process_events(xhci);
        if (!xhci_ring_busy(ring)) {
            uint32_t status = ring->evt.status;
            return (status >> 24) & 0xff;
        }
        if (nanoTime() > timeout_ns) {
            printk("XHCI event wait timeout!!!\n");
            printk("ring->eidx = %d\n", ring->eidx);
            printk("ring->nidx = %d\n", ring->nidx);
            struct xhci_ring *evts = xhci->evts;
            for (int i = 0; i < XHCI_RING_ITEMS; i++) {
                struct xhci_trb *e = &evts->ring[i];
                if (e->control || e->status || e->ptr_low || e->ptr_high) {
                    printk("Event[%d]: [%08x %08x %08x %08x] C=%d\n", i,
                           e->ptr_low, e->ptr_high, e->status, e->control,
                           !!(e->control & TRB_C));
                }
            }
            printk("Event ring nidx = %d\n", evts->nidx);
            ring->eidx = ring->nidx;
            return CC_USB_TRANSACTION_ERROR;
        }
        arch_pause();
    }
}

// Add a TRB to the given ring
static void xhci_trb_fill(struct xhci_ring *ring, void *data, uint32_t xferlen,
                          uint32_t flags) {
    struct xhci_trb *dst = &ring->ring[ring->nidx];
    if (flags & TRB_TR_IDT) {
        memcpy(&dst->ptr_low, data, xferlen);
    } else {
        uint64_t phys = data ? translate_address(get_current_page_dir(false),
                                                 (uint64_t)data)
                             : 0;
        dst->ptr_low = phys;
        dst->ptr_high = phys >> 32;
    }
    dst->status = xferlen;
    __sync_synchronize();
    dst->control = flags | (ring->cs ? TRB_C : 0);
    dma_sync_cpu_to_device(dst, sizeof(struct xhci_trb));
}

// Queue a TRB onto a ring, wrapping ring as needed
static void xhci_trb_queue(struct xhci_ring *ring, void *data, uint32_t xferlen,
                           uint32_t flags) {
    if (ring->nidx >= XHCI_RING_ITEMS - 1) {
        xhci_trb_fill(ring, ring->ring, 0, (TR_LINK << 10) | TRB_LK_TC);
        dma_sync_cpu_to_device(&ring->ring[ring->nidx],
                               sizeof(struct xhci_trb));
        ring->nidx = 0;
        ring->cs = !ring->cs;
    }

    xhci_trb_fill(ring, data, xferlen, flags);

    dma_sync_cpu_to_device(&ring->ring[ring->nidx], sizeof(struct xhci_trb));

    ring->nidx++;
}

static bool xhci_crosses_64kb_boundary(uint64_t phys_addr, uint32_t length) {
    if (length == 0)
        return false;

    uint64_t start_page = phys_addr >> 16;
    uint64_t end_page = (phys_addr + length - 1) >> 16;

    return start_page != end_page;
}

static uint32_t xhci_bytes_to_64kb_boundary(uint64_t phys_addr) {
    return 0x10000 - (phys_addr & 0xFFFF);
}

static void xhci_trb_queue_split(struct xhci_ring *ring, void *data,
                                 int datalen, uint32_t flags,
                                 bool is_last_in_td) {
    if (datalen == 0 || data == NULL) {
        return;
    }

    uint64_t phys =
        translate_address(get_current_page_dir(false), (uint64_t)data);

    if (!xhci_crosses_64kb_boundary(phys, datalen)) {
        xhci_trb_queue(ring, data, datalen, flags);
        return;
    }

    uint32_t offset = 0;
    int chunk_num = 0;

    while (offset < datalen) {
        uint64_t current_phys = phys + offset;
        uint32_t remaining = datalen - offset;
        uint32_t chunk_size;

        if (xhci_crosses_64kb_boundary(current_phys, remaining)) {
            chunk_size = xhci_bytes_to_64kb_boundary(current_phys);
        } else {
            chunk_size = remaining;
        }

        void *chunk_data = (void *)((uint64_t)data + offset);

        uint32_t chunk_flags = flags;
        bool is_last_chunk = (offset + chunk_size >= datalen);

        if (!is_last_chunk) {
            chunk_flags = (flags & ~TRB_TR_IOC) | TRB_TR_CH;
        } else if (!is_last_in_td) {
            chunk_flags = (flags & ~TRB_TR_IOC) | TRB_TR_CH;
        }

        xhci_trb_queue(ring, chunk_data, chunk_size, chunk_flags);

        offset += chunk_size;
        chunk_num++;
    }
}

// Submit a command to the xhci controller ring
static int xhci_cmd_submit(struct usb_xhci_s *xhci, struct xhci_inctx *inctx,
                           uint32_t flags) {
    uint32_t cmd_type = (flags >> TRB_TYPE_SHIFT) & TRB_TYPE_MASK;

    if (inctx) {
        dma_sync_cpu_to_device(inctx, (sizeof(struct xhci_inctx) * 33)
                                          << xhci->context64);
    }

    // 填充TRB
    uint32_t old_nidx = xhci->cmds->nidx;
    xhci_trb_queue(xhci->cmds, inctx, 0, flags);

    // 敲门铃
    xhci_doorbell(xhci, 0, 0);

    int rc = xhci_event_wait(xhci, xhci->cmds, 1000);

    if (rc != CC_SUCCESS) {
        printk("XHCI cmd submit failed!!! rc = %d\n", rc);
    }

    return rc;
}

static int xhci_cmd_enable_slot(struct usb_xhci_s *xhci) {
    int cc = xhci_cmd_submit(xhci, NULL, CR_ENABLE_SLOT << 10);
    if (cc != CC_SUCCESS)
        return -1;
    return (xhci->cmds->evt.control >> 24) & 0xff;
}

static int xhci_cmd_disable_slot(struct usb_xhci_s *xhci, uint32_t slotid) {
    return xhci_cmd_submit(xhci, NULL,
                           (CR_DISABLE_SLOT << 10) | (slotid << 24));
}

static int xhci_cmd_address_device(struct usb_xhci_s *xhci, uint32_t slotid,
                                   struct xhci_inctx *inctx) {
    return xhci_cmd_submit(xhci, inctx,
                           (CR_ADDRESS_DEVICE << 10) | (slotid << 24));
}

static int xhci_cmd_configure_endpoint(struct usb_xhci_s *xhci, uint32_t slotid,
                                       struct xhci_inctx *inctx) {
    return xhci_cmd_submit(xhci, inctx,
                           (CR_CONFIGURE_ENDPOINT << 10) | (slotid << 24));
}

static int xhci_cmd_evaluate_context(struct usb_xhci_s *xhci, uint32_t slotid,
                                     struct xhci_inctx *inctx) {
    return xhci_cmd_submit(xhci, inctx,
                           (CR_EVALUATE_CONTEXT << 10) | (slotid << 24));
}

static int xhci_cmd_stop_endpoint(struct usb_xhci_s *xhci, uint32_t slotid,
                                  uint32_t epid) {
    return xhci_cmd_submit(xhci, NULL,
                           (CR_STOP_ENDPOINT << 10) |
                               (slotid << TRB_CR_SLOTID_SHIFT) |
                               (epid << TRB_CR_EPID_SHIFT));
}

static int xhci_cmd_reset_endpoint(struct usb_xhci_s *xhci, uint32_t slotid,
                                   uint32_t epid) {
    return xhci_cmd_submit(xhci, NULL,
                           (CR_RESET_ENDPOINT << 10) |
                               (slotid << TRB_CR_SLOTID_SHIFT) |
                               (epid << TRB_CR_EPID_SHIFT));
}

static int xhci_cmd_set_tr_dequeue(struct usb_xhci_s *xhci, uint32_t slotid,
                                   uint32_t epid, uint64_t dequeue_ptr,
                                   uint32_t dcs) {
    uint64_t param = (dequeue_ptr & ~0xFULL) | (dcs & 1);

    if (xhci->cmds->nidx >= XHCI_RING_ITEMS - 1) {
        xhci_trb_fill(xhci->cmds, xhci->cmds->ring, 0,
                      (TR_LINK << 10) | TRB_LK_TC);
        dma_sync_cpu_to_device(&xhci->cmds->ring[xhci->cmds->nidx],
                               sizeof(struct xhci_trb));
        xhci->cmds->nidx = 0;
        xhci->cmds->cs = !xhci->cmds->cs;
    }

    struct xhci_trb *dst = &xhci->cmds->ring[xhci->cmds->nidx];
    dst->ptr_low = param;
    dst->ptr_high = param >> 32;
    dst->status = 0;
    __sync_synchronize();
    dst->control = (CR_SET_TR_DEQUEUE << 10) | (slotid << TRB_CR_SLOTID_SHIFT) |
                   (epid << TRB_CR_EPID_SHIFT) | (xhci->cmds->cs ? TRB_C : 0);
    dma_sync_cpu_to_device(dst, sizeof(struct xhci_trb));

    xhci->cmds->nidx++;

    // 敲门铃
    xhci_doorbell(xhci, 0, 0);

    int rc = xhci_event_wait(xhci, xhci->cmds, 1000);

    if (rc != CC_SUCCESS) {
        printk("XHCI set tr dequeue failed!!! rc = %d\n", rc);
    }

    return rc;
}

static int xhci_cmd_reset_device(struct usb_xhci_s *xhci, uint32_t slotid) {
    return xhci_cmd_submit(xhci, NULL,
                           (CR_RESET_DEVICE << 10) | (slotid << 24));
}

static struct xhci_inctx *xhci_alloc_inctx(struct usbdevice_s *usbdev,
                                           int maxepid) {
    struct usb_xhci_s *xhci =
        container_of(usbdev->hub->cntl, struct usb_xhci_s, usb);
    int size = (sizeof(struct xhci_inctx) * 33) << xhci->context64;
    struct xhci_inctx *in = alloc_frames_bytes_dma32(size);
    if (!in) {
        return NULL;
    }
    memset(in, 0, size);

    struct xhci_slotctx *slot = (void *)&in[1 << xhci->context64];
    slot->ctx[0] |= maxepid << 27; // context entries
    slot->ctx[0] |= speed_to_xhci[usbdev->speed] << 20;

    // Set high-speed hub flags.
    struct usbdevice_s *hubdev = usbdev->hub->usbdev;
    if (hubdev) {
        if (usbdev->speed == USB_LOWSPEED || usbdev->speed == USB_FULLSPEED) {
            struct xhci_pipe *hpipe =
                container_of(hubdev->defpipe, struct xhci_pipe, pipe);
            if (hubdev->speed == USB_HIGHSPEED) {
                slot->ctx[2] |= hpipe->slotid;
                slot->ctx[2] |= (usbdev->port + 1) << 8;
            } else {
                struct xhci_slotctx *hslot = (void *)phys_to_virt(
                    ((uint64_t)xhci->devs[hpipe->slotid].ptr_high << 32) |
                    xhci->devs[hpipe->slotid].ptr_low);
                slot->ctx[2] = hslot->ctx[2];
            }
        }
        uint32_t route = 0;
        while (usbdev->hub->usbdev) {
            route <<= 4;
            route |= (usbdev->port + 1) & 0xf;
            usbdev = usbdev->hub->usbdev;
        }
        slot->ctx[0] |= route;
    }

    slot->ctx[1] |= (usbdev->port + 1) << 16;

    return in;
}

static int xhci_config_hub(struct usbhub_s *hub) {
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    struct xhci_pipe *pipe =
        container_of(hub->usbdev->defpipe, struct xhci_pipe, pipe);
    struct xhci_slotctx *hdslot = (void *)phys_to_virt(
        ((uint64_t)xhci->devs[pipe->slotid].ptr_high << 32) |
        xhci->devs[pipe->slotid].ptr_low);
    if ((hdslot->ctx[3] >> 27) == 3)
        // Already configured
        return 0;
    struct xhci_inctx *in = xhci_alloc_inctx(hub->usbdev, 1);
    if (!in)
        return -1;
    in->add = 0x01;
    struct xhci_slotctx *slot = (void *)&in[1 << xhci->context64];
    slot->ctx[0] |= 1 << 26;
    slot->ctx[1] |= hub->portcount << 24;

    int cc = xhci_cmd_configure_endpoint(xhci, pipe->slotid, in);
    free_frames_bytes_dma32(in, (sizeof(struct xhci_inctx) * 33)
                                    << xhci->context64);
    if (cc != CC_SUCCESS) {
        return -1;
    }
    return 0;
}

static struct usb_pipe *
xhci_alloc_pipe(struct usbdevice_s *usbdev,
                struct usb_endpoint_descriptor *epdesc) {
    uint8_t eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    struct usb_xhci_s *xhci =
        container_of(usbdev->hub->cntl, struct usb_xhci_s, usb);
    struct xhci_pipe *pipe;
    uint32_t epid;

    if (epdesc->bEndpointAddress == 0) {
        epid = 1;
    } else {
        epid = (epdesc->bEndpointAddress & 0x0f) * 2;
        epid += (epdesc->bEndpointAddress & USB_DIR_IN) ? 1 : 0;
    }

    if (eptype == USB_ENDPOINT_XFER_CONTROL)
        pipe = alloc_frames_bytes_dma32(sizeof(*pipe));
    else
        pipe = alloc_frames_bytes_dma32(sizeof(*pipe));
    if (!pipe) {
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));

    usb_desc2pipe(&pipe->pipe, usbdev, epdesc);
    pipe->epid = epid;
    pipe->reqs.ring = alloc_frames_bytes_dma32(XHCI_RING_SIZE * 2);
    memset(pipe->reqs.ring, 0, XHCI_RING_SIZE * 2);
    dma_sync_cpu_to_device(pipe->reqs.ring, XHCI_RING_SIZE * 2);
    pipe->reqs.cs = 1;

    // Allocate input context and initialize endpoint info.
    struct xhci_inctx *in = xhci_alloc_inctx(usbdev, epid);
    if (!in)
        goto fail;
    in->add = 0x01 | (1 << epid);
    struct xhci_epctx *ep = (void *)&in[(pipe->epid + 1) << xhci->context64];
    if (eptype == USB_ENDPOINT_XFER_INT)
        ep->ctx[0] = (usb_get_period(usbdev, epdesc) + 3) << 16;
    ep->ctx[1] |= eptype << 3;
    if (epdesc->bEndpointAddress & USB_DIR_IN ||
        eptype == USB_ENDPOINT_XFER_CONTROL)
        ep->ctx[1] |= 1 << 5;
    ep->ctx[1] |= pipe->pipe.maxpacket << 16;
    uint64_t deq = translate_address(get_current_page_dir(false),
                                     (uint64_t)&pipe->reqs.ring[0]);
    ep->deq_low = deq;
    ep->deq_high = deq >> 32;
    ep->deq_low |= 1; // dcs
    ep->length = pipe->pipe.maxpacket;

    if (pipe->epid == 1) {
        if (usbdev->hub->usbdev) {
            int ret = xhci_config_hub(usbdev->hub);
            if (ret)
                goto fail;
        }

        uint32_t size = (sizeof(struct xhci_slotctx) * 32) << xhci->context64;
        struct xhci_slotctx *dev = alloc_frames_bytes_dma32(size);
        if (!dev) {
            goto fail;
        }

        int slotid = xhci_cmd_enable_slot(xhci);
        if (slotid < 0) {
            free_frames_bytes_dma32(dev, size);
            goto fail;
        }

        memset(dev, 0, size);

        // 刷新设备上下文
        dma_sync_cpu_to_device(dev, size);

        uint64_t dcba =
            translate_address(get_current_page_dir(false), (uint64_t)dev);
        xhci->devs[slotid].ptr_low = dcba;
        xhci->devs[slotid].ptr_high = dcba >> 32;

        // 刷新devs数组项
        dma_sync_cpu_to_device(&xhci->devs[slotid], sizeof(xhci->devs[slotid]));

        int cc = xhci_cmd_address_device(xhci, slotid, in);
        if (cc != CC_SUCCESS) {
            xhci_cmd_disable_slot(xhci, slotid);
            xhci->devs[slotid].ptr_low = 0;
            xhci->devs[slotid].ptr_high = 0;
            free_frames_bytes_dma32(dev, size);
            goto fail;
        }
        pipe->slotid = slotid;
    } else {
        struct xhci_pipe *defpipe =
            container_of(usbdev->defpipe, struct xhci_pipe, pipe);
        pipe->slotid = defpipe->slotid;
        // Send configure command.
        int cc = xhci_cmd_configure_endpoint(xhci, pipe->slotid, in);
        if (cc != CC_SUCCESS) {
            goto fail;
        }
    }
    free_frames_bytes_dma32(in, (sizeof(struct xhci_inctx) * 33)
                                    << xhci->context64);
    xhci->pipes[pipe->slotid][pipe->epid] = pipe;
    return &pipe->pipe;

fail:
    printk("xhci alloc pipe failed!!!\n");
    free_frames_bytes_dma32(pipe, sizeof(*pipe));
    free_frames_bytes_dma32(in, (sizeof(struct xhci_inctx) * 33)
                                    << xhci->context64);
    return NULL;
}

struct usb_pipe *xhci_realloc_pipe(struct usbdevice_s *usbdev,
                                   struct usb_pipe *upipe,
                                   struct usb_endpoint_descriptor *epdesc) {
    if (!epdesc) {
        struct xhci_pipe *pipe = container_of(upipe, struct xhci_pipe, pipe);
        struct usb_xhci_s *xhci =
            container_of(upipe->cntl, struct usb_xhci_s, usb);
        xhci->pipes[pipe->slotid][pipe->epid] = NULL;
        usb_add_freelist(upipe);
        return NULL;
    }
    if (!upipe)
        return xhci_alloc_pipe(usbdev, epdesc);
    uint8_t eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    int oldmaxpacket = upipe->maxpacket;
    usb_desc2pipe(upipe, usbdev, epdesc);
    struct xhci_pipe *pipe = container_of(upipe, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(upipe->cntl, struct usb_xhci_s, usb);
    if (eptype != USB_ENDPOINT_XFER_CONTROL || upipe->maxpacket == oldmaxpacket)
        return upipe;

    // maxpacket has changed on control endpoint - update controller.
    struct xhci_inctx *in = xhci_alloc_inctx(usbdev, 1);
    if (!in)
        return upipe;
    in->add = (1 << 1);
    struct xhci_epctx *ep = (void *)&in[2 << xhci->context64];
    ep->ctx[1] |= (pipe->pipe.maxpacket << 16);
    int cc = xhci_cmd_evaluate_context(xhci, pipe->slotid, in);
    // if (cc != CC_SUCCESS) {
    //     dprintf(1, "%s: reconf ctl endpoint: failed (cc %d)\n", __func__,
    //     cc);
    // }
    int size = (sizeof(struct xhci_inctx) * 33) << xhci->context64;
    free_frames_bytes_dma32(in, size);

    return upipe;
}

static void xhci_xfer_setup(struct xhci_pipe *pipe, int dir, void *cmd,
                            void *data, int datalen) {
    struct usb_xhci_s *xhci =
        container_of(pipe->pipe.cntl, struct usb_xhci_s, usb);

    // Setup Stage TRT 字段
    uint32_t trt;
    if (datalen == 0) {
        trt = 0; // No Data Stage
    } else if (dir) {
        trt = 3; // IN Data Stage
    } else {
        trt = 2; // OUT Data Stage
    }

    xhci_trb_queue(&pipe->reqs, cmd, USB_CONTROL_SETUP_SIZE,
                   (TR_SETUP << 10) | TRB_TR_IDT | (trt << 16));

    if (datalen && data) {
        uint32_t data_flags = (TR_DATA << 10) | (dir ? TRB_TR_DIR : 0);

        xhci_trb_queue_split(&pipe->reqs, data, datalen, data_flags, false);
    }

    uint32_t status_dir;
    if (datalen == 0) {
        status_dir = 1;
    } else if (dir) {
        status_dir = 0;
    } else {
        status_dir = 1;
    }

    xhci_trb_queue(&pipe->reqs, NULL, 0,
                   (TR_STATUS << 10) | TRB_TR_IOC |
                       (status_dir ? TRB_TR_DIR : 0));

    xhci_doorbell(xhci, pipe->slotid, pipe->epid);
}

static void xhci_xfer_normal(struct xhci_pipe *pipe, void *data, int datalen) {
    struct usb_xhci_s *xhci =
        container_of(pipe->pipe.cntl, struct usb_xhci_s, usb);

    xhci_trb_queue_split(&pipe->reqs, data, datalen,
                         (TR_NORMAL << 10) | TRB_TR_IOC, true);

    xhci_doorbell(xhci, pipe->slotid, pipe->epid);
}

static int xhci_stop_endpoint_safe(struct usb_xhci_s *xhci, uint32_t slotid,
                                   uint32_t epid) {
    int cc = xhci_cmd_stop_endpoint(xhci, slotid, epid);

    switch (cc) {
    case CC_SUCCESS:
        return 0;

    case CC_CONTEXT_STATE_ERROR:
        // Endpoint已经stopped或disabled
        return 0;

    default:
        printk("Stop endpoint failed: CC=%d\n", cc);
        return -1;
    }
}

int xhci_send_pipe(struct usb_pipe *p, int dir, const void *cmd, void *data,
                   int datalen) {
    struct xhci_pipe *pipe = container_of(p, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(p->cntl, struct usb_xhci_s, usb);

    int ret = -1;

    if (data && datalen > 0) {
        dma_sync_cpu_to_device(data, datalen);
    }

    if (cmd) {
        const struct usb_ctrlrequest *req = cmd;

        if (req->bRequest == USB_REQ_SET_ADDRESS) {
            return 0;
        }

        xhci_xfer_setup(pipe, dir, cmd, data, datalen);
    } else {
        xhci_xfer_normal(pipe, data, datalen);
    }

    int cc = xhci_event_wait(xhci, &pipe->reqs, usb_xfer_time(p, datalen));

    if (cc != CC_SUCCESS && cc != CC_SHORT_PACKET) {
        printk("%s: xfer failed (cc %d)\n", __func__, cc);
        printk("pipe->transfer_count = %d\n", pipe->transfer_count);
        goto cleanup;
    }

    pipe->transfer_count++;

    if (dir && data) {
        uint32_t residue = pipe->reqs.evt.status & 0xFFFFFF;
        int actual = datalen - residue;

        if (actual > 0) {
            dma_sync_device_to_cpu(data, actual);
        }
    }

    ret = 0; // 成功

cleanup:
    return ret;
}

int xhci_send_intr_pipe(struct usb_pipe *p, void *buf, int len, intr_xfer_cb cb,
                        void *user_data) {
    struct xhci_pipe *pipe = container_of(p, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(p->cntl, struct usb_xhci_s, usb);

    pipe->intr_xfer = cb;
    pipe->intr_xfer_data = user_data;

    xhci_xfer_normal(pipe, buf, len);

    return 0;
}

int xhci_hcd_driver_probe(pci_device_t *pci_dev, uint32_t vendor_device_id) {
    // Find MMIO BAR
    uint64_t mmio_base = 0;
    uint64_t mmio_size = 0;
    for (int i = 0; i < 6; i++) {
        if (pci_dev->bars[i].size > 0 && pci_dev->bars[i].mmio) {
            mmio_base = pci_dev->bars[i].address;
            mmio_size = pci_dev->bars[i].size;
            break;
        }
    }

    if (mmio_base == 0) {
        printk("xhci: No MMIO BAR found\n");
        return -1;
    }

    // Map MMIO region
    void *mmio_vaddr = (void *)phys_to_virt(mmio_base);
    map_page_range(get_current_page_dir(false), (uint64_t)mmio_vaddr, mmio_base,
                   mmio_size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);

    struct usb_xhci_s *xhci = xhci_controller_setup(mmio_vaddr);
    xhci->usb.pci = pci_dev;
    xhci->pci_dev = pci_dev;
    configure_xhci(xhci);
    pci_dev->desc = xhci;

    return 0;
}

void xhci_hcd_driver_remove(pci_device_t *dev) {}

void xhci_hcd_driver_shutdown(pci_device_t *dev) {}

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
