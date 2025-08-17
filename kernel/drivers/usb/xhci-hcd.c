#include "xhci-hcd.h"
#include "usb.h"

// --------------------------------------------------------------
// configuration

#define XHCI_RING_ITEMS 16
#define XHCI_RING_SIZE (XHCI_RING_ITEMS * sizeof(struct xhci_trb))

/*
 *  xhci_ring structs are allocated with XHCI_RING_SIZE alignment,
 *  then we can get it from a trb pointer (provided by evt ring).
 */
#define XHCI_RING(_trb) \
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

typedef enum TRBType
{
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

typedef enum TRBCCode
{
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

enum
{
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

#define xhci_get_field(data, field) \
    (((data) >> field##_SHIFT) & field##_MASK)

// --------------------------------------------------------------
// state structs

struct xhci_ring
{
    struct xhci_trb ring[XHCI_RING_ITEMS];
    struct xhci_trb evt;
    uint32_t eidx;
    uint32_t nidx;
    uint32_t cs;
    spinlock_t lock;
};

struct xhci_portmap
{
    uint8_t start;
    uint8_t count;
};

struct usb_xhci_s
{
    struct usb_s usb;

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
};

struct xhci_pipe
{
    struct xhci_ring reqs;

    struct usb_pipe pipe;
    uint32_t slotid;
    uint32_t epid;
    void *buf;
    int bufused;
};

// --------------------------------------------------------------
// tables

static const char *speed_name[16] = {
    [0] = " - ",
    [1] = "Full",
    [2] = "Low",
    [3] = "High",
    [4] = "Super",
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

static int wait_bit(uint32_t *reg, uint32_t mask, int value, uint32_t timeout)
{
    while ((*reg & mask) != value)
    {
        arch_pause();
    }
    return 0;
}

/****************************************************************
 * Root hub
 ****************************************************************/

#define XHCI_TIME_POSTPOWER 20

// Check if device attached to port
static int
xhci_hub_detect(struct usbhub_s *hub, uint32_t port)
{
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    uint32_t portsc = xhci->pr[port].portsc;
    return (portsc & XHCI_PORTSC_CCS) ? 1 : 0;
}

#define XHCI_RESET_TIMEOUT_MS 1000

// Reset device on port
static int
xhci_hub_reset(struct usbhub_s *hub, uint32_t port)
{
    struct usb_xhci_s *xhci = container_of(hub->cntl, struct usb_xhci_s, usb);
    uint32_t portsc = xhci->pr[port].portsc;
    if (!(portsc & XHCI_PORTSC_CCS))
        // Device no longer connected?!
        return -1;

    uint8_t pls = xhci_get_field(portsc, XHCI_PORTSC_PLS);
    switch (pls)
    {
    case PLS_U0:
        // A USB3 port - controller automatically performs reset
        break;
    case PLS_POLLING:
        // A USB2 port - perform device reset
        xhci->pr[port].portsc = portsc | XHCI_PORTSC_PR;
        break;
    default:
        printf("XHCI reset: unknown pls %d\n", pls);
        return -1;
    }

    uint64_t start_ns = nanoTime();

    // Wait for device to complete reset and be enabled
    for (;;)
    {
        portsc = xhci->pr[port].portsc;
        if (!(portsc & XHCI_PORTSC_CCS))
            // Device disconnected during reset
            return -1;
        if (portsc & XHCI_PORTSC_PED)
            // Reset complete
            break;
        arch_pause();
        if ((nanoTime() - start_ns) > (XHCI_RESET_TIMEOUT_MS * 1000000))
        {
            printf("XHCI reset: timeout waiting for port %d to reset\n", port);
            return -1;
        }
    }

    int rc = speed_from_xhci[xhci_get_field(portsc, XHCI_PORTSC_SPEED)];
    printf("XHCI reset: port %d reset complete, speed %s\n", port, speed_name[xhci_get_field(portsc, XHCI_PORTSC_SPEED)]);
    return rc;
}

static int
xhci_hub_portmap(struct usbhub_s *hub, uint32_t vport)
{
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

static void
xhci_hub_disconnect(struct usbhub_s *hub, uint32_t port)
{
    // XXX - should turn the port power off.
}

static struct usbhub_op_s xhci_hub_ops = {
    .detect = xhci_hub_detect,
    .reset = xhci_hub_reset,
    .portmap = xhci_hub_portmap,
    .disconnect = xhci_hub_disconnect,
};

// Find any devices connected to the root hub.
static int xhci_check_ports(struct usb_xhci_s *xhci)
{
    struct usbhub_s hub;
    memset(&hub, 0, sizeof(hub));
    hub.cntl = &xhci->usb;
    hub.portcount = xhci->ports;
    hub.op = &xhci_hub_ops;
    usb_enumerate(&hub);
    return hub.devcount;
}

/****************************************************************
 * Setup
 ****************************************************************/

static void
xhci_free_pipes(struct usb_xhci_s *xhci)
{
    // XXX - should walk list of pipes and free unused pipes.
}

void xhci_poll_task(uint64_t arg);

static int
configure_xhci(void *data)
{
    struct usb_xhci_s *xhci = data;
    uint32_t reg;

    xhci->devs = alloc_frames_bytes(sizeof(*xhci->devs) * (xhci->slots + 1));
    xhci->eseg = alloc_frames_bytes(sizeof(*xhci->eseg));
    xhci->cmds = alloc_frames_bytes(sizeof(*xhci->cmds));
    xhci->evts = alloc_frames_bytes(sizeof(*xhci->evts));
    if (!xhci->devs || !xhci->cmds || !xhci->evts || !xhci->eseg)
    {
        goto fail;
    }
    memset(xhci->devs, 0, sizeof(*xhci->devs) * (xhci->slots + 1));
    memset(xhci->cmds, 0, sizeof(*xhci->cmds));
    memset(xhci->evts, 0, sizeof(*xhci->evts));
    memset(xhci->eseg, 0, sizeof(*xhci->eseg));

    reg = xhci->op->usbcmd;
    if (reg & XHCI_CMD_RS)
    {
        reg &= ~XHCI_CMD_RS;
        xhci->op->usbcmd = reg;
        if (wait_bit(&xhci->op->usbsts, XHCI_STS_HCH, XHCI_STS_HCH, 32) != 0)
            goto fail;
    }

    xhci->op->usbcmd = XHCI_CMD_HCRST;
    if (wait_bit(&xhci->op->usbcmd, XHCI_CMD_HCRST, 0, 10000) != 0)
        goto fail;
    if (wait_bit(&xhci->op->usbsts, XHCI_STS_CNR, 0, 10000) != 0)
        goto fail;

    xhci->op->config = xhci->slots;
    uint64_t devs_phys = translate_address(get_current_page_dir(false), (uint64_t)xhci->devs);
    xhci->op->dcbaap_low = (uint32_t)(devs_phys & 0xFFFFFFFF);
    xhci->op->dcbaap_high = (uint32_t)(devs_phys >> 32);
    uint64_t cmds_phys = translate_address(get_current_page_dir(false), (uint64_t)xhci->cmds);
    xhci->op->crcr_low = (uint32_t)(cmds_phys & 0xFFFFFFFF) | 1;
    xhci->op->crcr_high = (uint32_t)(cmds_phys >> 32);
    xhci->cmds->cs = 1;

    uint64_t evts_phys = translate_address(get_current_page_dir(false), (uint64_t)xhci->evts);
    xhci->eseg->ptr_low = (uint32_t)(evts_phys & 0xFFFFFFFF);
    xhci->eseg->ptr_high = (uint32_t)(evts_phys >> 32);
    xhci->eseg->size = XHCI_RING_ITEMS;
    xhci->ir->erstsz = 1;
    xhci->ir->erdp_low = (uint32_t)(evts_phys & 0xFFFFFFFF);
    xhci->ir->erdp_high = (uint32_t)(evts_phys >> 32);
    uint64_t eseg_phys = translate_address(get_current_page_dir(false), (uint64_t)xhci->eseg);
    xhci->ir->erstba_low = (uint32_t)(eseg_phys & 0xFFFFFFFF);
    xhci->ir->erstba_high = (uint32_t)(eseg_phys >> 32);
    xhci->evts->cs = 1;

    reg = xhci->caps->hcsparams2;
    uint32_t spb = (reg >> 21 & 0x1f) << 5 | reg >> 27;
    if (spb)
    {
        uint64_t *spba = alloc_frames_bytes(sizeof(*spba) * spb);
        void *pad = alloc_frames_bytes(DEFAULT_PAGE_SIZE * spb);
        if (!spba || !pad)
        {
            free(spba);
            free(pad);
            goto fail;
        }
        int i;
        for (i = 0; i < spb; i++)
            spba[i] = translate_address(get_current_page_dir(false), (uint64_t)pad) + (i * DEFAULT_PAGE_SIZE);
        uint64_t spba_phys = translate_address(get_current_page_dir(false), (uint64_t)spba);
        xhci->devs[0].ptr_low = (uint32_t)(spba_phys & 0xFFFFFFFF);
        xhci->devs[0].ptr_high = (uint32_t)(spba_phys >> 32);
    }

    reg = xhci->op->usbcmd;
    reg |= XHCI_CMD_RS;
    xhci->op->usbcmd = reg;

    task_create("xhci_poll_task", xhci_poll_task, (uint64_t)xhci);

    // Find devices
    int count = xhci_check_ports(xhci);

    printf("Found %d USB devices on XHCI controller\n", count);

    // xhci_free_pipes(xhci);
    // if (count)
    // Success
    return 0;

    // // No devices found - shutdown and free controller.
    // reg = xhci->op->usbcmd;
    // reg &= ~XHCI_CMD_RS;
    // xhci->op->usbcmd = reg;
    // wait_bit(&xhci->op->usbsts, XHCI_STS_HCH, XHCI_STS_HCH, 32);

fail:
    printf("Configure XHCI failed");

    free_frames_bytes(xhci->eseg, sizeof(*xhci->eseg));
    free_frames_bytes(xhci->evts, sizeof(*xhci->evts));
    free_frames_bytes(xhci->cmds, sizeof(*xhci->cmds));
    free_frames_bytes(xhci->devs, sizeof(*xhci->devs) * (xhci->slots + 1));
    free(xhci);

    return -1;
}

static struct usb_xhci_s *xhci_controller_setup(void *baseaddr)
{
    struct usb_xhci_s *xhci = malloc(sizeof(*xhci));
    if (!xhci)
    {
        return NULL;
    }
    memset(xhci, 0, sizeof(*xhci));
    xhci->caps = baseaddr;
    xhci->op = baseaddr + xhci->caps->caplength;
    xhci->pr = baseaddr + xhci->caps->caplength + 0x400;
    xhci->db = baseaddr + xhci->caps->dboff;
    xhci->ir = baseaddr + xhci->caps->rtsoff + 0x20;

    uint32_t hcs1 = xhci->caps->hcsparams1;
    uint32_t hcc = xhci->caps->hccparams;
    xhci->ports = (hcs1 >> 24) & 0xff;
    xhci->slots = hcs1 & 0xff;
    xhci->xcap = ((hcc >> 16) & 0xffff) << 2;
    xhci->context64 = (hcc & 0x04) ? 1 : 0;
    xhci->usb.resetlock.lock = 0;
    xhci->usb.type = USB_TYPE_XHCI;

    if (xhci->xcap)
    {
        uint32_t off;
        void *addr = (void *)(baseaddr + xhci->xcap);
        do
        {
            struct xhci_xcap *xcap = addr;
            uint32_t ports, name, cap = xcap->cap;
            switch (cap & 0xff)
            {
            case 0x02:
                name = xcap->data[0];
                ports = xcap->data[1];
                uint8_t major = (cap >> 24) & 0xff;
                uint8_t minor = (cap >> 16) & 0xff;
                uint8_t count = (ports >> 8) & 0xff;
                uint8_t start = (ports >> 0) & 0xff;
                if (name == 0x20425355 /* "USB " */)
                {
                    if (major == 2)
                    {
                        xhci->usb2.start = start;
                        xhci->usb2.count = count;
                    }
                    if (major == 3)
                    {
                        xhci->usb3.start = start;
                        xhci->usb3.count = count;
                    }
                }
                break;
            default:
                break;
            }
            off = (cap >> 8) & 0xff;
            addr += off << 2;
        } while (off > 0);
    }

    uint32_t pagesize = xhci->op->pagesize;
    if (DEFAULT_PAGE_SIZE != (pagesize << 12))
    {
        printf("XHCI: Invalid page size %d\n", pagesize);
        free(xhci);
        return NULL;
    }

    return xhci;
}

/****************************************************************
 * End point communication
 ****************************************************************/

// Signal the hardware to process events on a TRB ring
static void xhci_doorbell(struct usb_xhci_s *xhci, uint32_t slotid, uint32_t value)
{
    struct xhci_db *db = xhci->db;
    void *addr = &db[slotid].doorbell;
    *(uint32_t *)(addr) = value;
}

// Dequeue events on the XHCI command ring generated by the hardware
static void xhci_process_events(struct usb_xhci_s *xhci)
{
    struct xhci_ring *evts = xhci->evts;

    for (;;)
    {
        /* check for event */
        uint32_t nidx = evts->nidx;
        uint32_t cs = evts->cs;
        struct xhci_trb *etrb = evts->ring + nidx;
        uint32_t control = etrb->control;
        if ((control & TRB_C) != (cs ? 1 : 0))
            return;

        /* process event */
        uint32_t evt_type = TRB_TYPE(control);
        uint32_t evt_cc = (etrb->status >> 24) & 0xff;
        switch (evt_type)
        {
        case ER_TRANSFER:
        case ER_COMMAND_COMPLETE:
        {
            struct xhci_trb *rtrb = (void *)(etrb->ptr_low | (uint64_t)etrb->ptr_high << 32);
            struct xhci_ring *ring = XHCI_RING(rtrb);
            struct xhci_trb *evt = &ring->evt;
            uint32_t eidx = rtrb - ring->ring + 1;
            memcpy(phys_to_virt(evt), phys_to_virt(etrb), sizeof(*etrb));
            phys_to_virt(ring)->eidx = eidx;
            break;
        }
        case ER_PORT_STATUS_CHANGE:
        {
            uint32_t port = ((etrb->ptr_low >> 24) & 0xff) - 1;
            // Read status, and clear port status chancge bits
            uint32_t portsc = xhci->pr[port].portsc;
            uint32_t pclear = (((portsc & ~(XHCI_PORTSC_PED | XHCI_PORTSC_PR)) & ~(XHCI_PORTSC_PLS_MASK << XHCI_PORTSC_PLS_SHIFT)) | (1 << XHCI_PORTSC_PLS_SHIFT));
            xhci->pr[port].portsc = pclear;

            break;
        }
        default:
            break;
        }

        /* move ring index, notify xhci */
        nidx++;
        if (nidx == XHCI_RING_ITEMS)
        {
            nidx = 0;
            cs = cs ? 0 : 1;
            evts->cs = cs;
        }
        evts->nidx = nidx;
        struct xhci_ir *ir = xhci->ir;
        uint64_t erdp = translate_address(get_current_page_dir(false), (uint64_t)(evts->ring + nidx));
        ir->erdp_low = (uint32_t)(erdp & 0xFFFFFFFF);
        ir->erdp_high = (uint32_t)(erdp >> 32);
    }
}

// Check if a ring has any pending TRBs
static int xhci_ring_busy(struct xhci_ring *ring)
{
    uint32_t eidx = ring->eidx;
    uint32_t nidx = ring->nidx;
    return (eidx != nidx);
}

void xhci_poll_task(uint64_t arg)
{
    struct usb_xhci_s *xhci = (struct usb_xhci_s *)arg;

    while (1)
    {
        xhci_process_events(xhci);

        arch_pause();
    }
}

// Wait for a ring to empty (all TRBs processed by hardware)
static int xhci_event_wait(struct usb_xhci_s *xhci,
                           struct xhci_ring *ring,
                           uint32_t timeout)
{
    // uint64_t timeout_ns = (uint64_t)timeout * 1000000; // Convert ms to ns
    // uint64_t start_ns = nanoTime();

    for (;;)
    {
        if (!xhci_ring_busy(ring))
        {
            uint32_t status = ring->evt.status;
            return (status >> 24) & 0xff;
        }
        arch_pause();
        // if (nanoTime() - start_ns > timeout_ns)
        // {
        //     printf("XHCI event wait timeout\n");
        //     return CC_INVALID; // Timeout
        // }
    }
}

// Add a TRB to the given ring
static void xhci_trb_fill(struct xhci_ring *ring, void *data, uint32_t xferlen, uint32_t flags)
{
    struct xhci_trb *dst = &ring->ring[ring->nidx];
    if (flags & TRB_TR_IDT)
    {
        memcpy(&dst->ptr_low, data, xferlen);
    }
    else
    {
        uint64_t data_ptr = translate_address(get_current_page_dir(false), (uint64_t)data);
        dst->ptr_low = (uint32_t)(data_ptr & 0xFFFFFFFF);
        dst->ptr_high = (uint32_t)(data_ptr >> 32);
    }
    dst->status = xferlen;
    dst->control = flags | (ring->cs ? TRB_C : 0);
}

// Queue a TRB onto a ring, wrapping ring as needed
static void xhci_trb_queue(struct xhci_ring *ring,
                           void *data, uint32_t xferlen, uint32_t flags)
{
    if (ring->nidx >= ARRAY_SIZE(ring->ring) - 1)
    {
        xhci_trb_fill(ring, ring->ring, 0, (TR_LINK << 10) | TRB_LK_TC);
        ring->nidx = 0;
        ring->cs ^= 1;
    }

    xhci_trb_fill(ring, data, xferlen, flags);
    ring->nidx++;
}

// Submit a command to the xhci controller ring
static int xhci_cmd_submit(struct usb_xhci_s *xhci, struct xhci_inctx *inctx, uint32_t flags)
{
    if (inctx)
    {
        struct xhci_slotctx *slot = (void *)&inctx[1 << xhci->context64];
        uint32_t port = ((slot->ctx[1] >> 16) & 0xff) - 1;
        uint32_t portsc = xhci->pr[port].portsc;
        if (!(portsc & XHCI_PORTSC_CCS))
        {
            // Device no longer connected?!
            return -1;
        }
    }

    spin_lock(&xhci->cmds->lock);
    xhci_trb_queue(xhci->cmds, inctx, 0, flags);
    xhci_doorbell(xhci, 0, 0);
    int rc = xhci_event_wait(xhci, xhci->cmds, 1000);
    spin_unlock(&xhci->cmds->lock);
    return rc;
}

static int xhci_cmd_enable_slot(struct usb_xhci_s *xhci)
{
    int cc = xhci_cmd_submit(xhci, NULL, CR_ENABLE_SLOT << 10);
    if (cc != CC_SUCCESS)
        return -1;
    return (xhci->cmds->evt.control >> 24) & 0xff;
}

static int xhci_cmd_disable_slot(struct usb_xhci_s *xhci, uint32_t slotid)
{
    return xhci_cmd_submit(xhci, NULL, (CR_DISABLE_SLOT << 10) | (slotid << 24));
}

static int xhci_cmd_address_device(struct usb_xhci_s *xhci, uint32_t slotid, struct xhci_inctx *inctx)
{
    return xhci_cmd_submit(xhci, inctx, (CR_ADDRESS_DEVICE << 10) | (slotid << 24));
}

static int xhci_cmd_configure_endpoint(struct usb_xhci_s *xhci, uint32_t slotid, struct xhci_inctx *inctx)
{
    return xhci_cmd_submit(xhci, inctx, (CR_CONFIGURE_ENDPOINT << 10) | (slotid << 24));
}

static int xhci_cmd_evaluate_context(struct usb_xhci_s *xhci, uint32_t slotid, struct xhci_inctx *inctx)
{
    return xhci_cmd_submit(xhci, inctx, (CR_EVALUATE_CONTEXT << 10) | (slotid << 24));
}

static struct xhci_inctx *
xhci_alloc_inctx(struct usbdevice_s *usbdev, int maxepid)
{
    struct usb_xhci_s *xhci = container_of(
        usbdev->hub->cntl, struct usb_xhci_s, usb);
    int size = (sizeof(struct xhci_inctx) * 33) << xhci->context64;
    struct xhci_inctx *in = alloc_frames_bytes(size);
    if (!in)
    {
        return NULL;
    }
    memset(in, 0, size);

    struct xhci_slotctx *slot = (void *)&in[1 << xhci->context64];
    slot->ctx[0] |= maxepid << 27; // context entries
    slot->ctx[0] |= speed_to_xhci[usbdev->speed] << 20;

    // Set high-speed hub flags.
    struct usbdevice_s *hubdev = usbdev->hub->usbdev;
    if (hubdev)
    {
        if (usbdev->speed == USB_LOWSPEED || usbdev->speed == USB_FULLSPEED)
        {
            struct xhci_pipe *hpipe = container_of(
                hubdev->defpipe, struct xhci_pipe, pipe);
            if (hubdev->speed == USB_HIGHSPEED)
            {
                slot->ctx[2] |= hpipe->slotid;
                slot->ctx[2] |= (usbdev->port + 1) << 8;
            }
            else
            {
                struct xhci_slotctx *hslot = (void *)(xhci->devs[hpipe->slotid].ptr_low | (uint64_t)xhci->devs[hpipe->slotid].ptr_high << 32);
                slot->ctx[2] = hslot->ctx[2];
            }
        }
        uint32_t route = 0;
        while (usbdev->hub->usbdev)
        {
            route <<= 4;
            route |= (usbdev->port + 1) & 0xf;
            usbdev = usbdev->hub->usbdev;
        }
        slot->ctx[0] |= route;
    }

    slot->ctx[1] |= (usbdev->port + 1) << 16;

    return in;
}

static int xhci_config_hub(struct usbhub_s *hub)
{
    struct usb_xhci_s *xhci = container_of(
        hub->cntl, struct usb_xhci_s, usb);
    struct xhci_pipe *pipe = container_of(
        hub->usbdev->defpipe, struct xhci_pipe, pipe);
    struct xhci_slotctx *hdslot = (void *)(xhci->devs[pipe->slotid].ptr_low | (uint64_t)xhci->devs[pipe->slotid].ptr_high << 32);
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
    free_frames_bytes(in, (sizeof(struct xhci_inctx) * 33) << xhci->context64);
    if (cc != CC_SUCCESS)
    {
        return -1;
    }
    return 0;
}

static struct usb_pipe *
xhci_alloc_pipe(struct usbdevice_s *usbdev, struct usb_endpoint_descriptor *epdesc)
{
    uint8_t eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    struct usb_xhci_s *xhci = container_of(
        usbdev->hub->cntl, struct usb_xhci_s, usb);
    struct xhci_pipe *pipe;
    uint32_t epid;

    if (epdesc->bEndpointAddress == 0)
    {
        epid = 1;
    }
    else
    {
        epid = (epdesc->bEndpointAddress & 0x0f) * 2;
        epid += (epdesc->bEndpointAddress & USB_DIR_IN) ? 1 : 0;
    }

    if (eptype == USB_ENDPOINT_XFER_CONTROL)
        pipe = alloc_frames_bytes(sizeof(*pipe));
    else
        pipe = alloc_frames_bytes(sizeof(*pipe));
    if (!pipe)
    {
        return NULL;
    }
    memset(pipe, 0, sizeof(*pipe));

    usb_desc2pipe(&pipe->pipe, usbdev, epdesc);
    pipe->epid = epid;
    pipe->reqs.cs = 1;
    if (eptype == USB_ENDPOINT_XFER_INT)
    {
        pipe->buf = malloc(pipe->pipe.maxpacket);
        if (!pipe->buf)
        {
            free(pipe);
            return NULL;
        }
    }

    // Allocate input context and initialize endpoint info.
    struct xhci_inctx *in = xhci_alloc_inctx(usbdev, epid);
    if (!in)
        goto fail;
    in->add = 0x01 | (1 << epid);
    struct xhci_epctx *ep = (void *)&in[(pipe->epid + 1) << xhci->context64];
    if (eptype == USB_ENDPOINT_XFER_INT)
        ep->ctx[0] = (usb_get_period(usbdev, epdesc) + 3) << 16;
    ep->ctx[1] |= eptype << 3;
    if (epdesc->bEndpointAddress & USB_DIR_IN || eptype == USB_ENDPOINT_XFER_CONTROL)
        ep->ctx[1] |= 1 << 5;
    ep->ctx[1] |= pipe->pipe.maxpacket << 16;
    uint64_t ring_addr = (uint64_t)&pipe->reqs.ring[0];
    uint64_t phys = translate_address(get_current_page_dir(false), ring_addr);
    ep->deq_low = (uint32_t)(phys & 0xFFFFFFFF) | 1;
    ep->deq_high = (uint32_t)(phys >> 32);
    ep->length = pipe->pipe.maxpacket;

    if (pipe->epid == 1)
    {
        if (usbdev->hub->usbdev)
        {
            // Make sure parent hub is configured.
            int ret = xhci_config_hub(usbdev->hub);
            if (ret)
                goto fail;
        }
        // Enable slot.
        uint32_t size = (sizeof(struct xhci_slotctx) * 32) << xhci->context64;
        struct xhci_slotctx *dev = alloc_frames_bytes(size);
        if (!dev)
        {
            goto fail;
        }
        int slotid = xhci_cmd_enable_slot(xhci);
        if (slotid < 0)
        {
            free(dev);
            goto fail;
        }
        memset(dev, 0, size);
        uint64_t dev_phys = translate_address(get_current_page_dir(false), (uint64_t)dev);
        xhci->devs[slotid].ptr_low = (uint32_t)(dev_phys & 0xFFFFFFFF);
        xhci->devs[slotid].ptr_high = (uint32_t)(dev_phys >> 32);

        // Send set_address command.
        int cc = xhci_cmd_address_device(xhci, slotid, in);
        if (cc != CC_SUCCESS)
        {
            cc = xhci_cmd_disable_slot(xhci, slotid);
            if (cc != CC_SUCCESS)
            {
                goto fail;
            }
            xhci->devs[slotid].ptr_low = 0;
            xhci->devs[slotid].ptr_high = 0;
            free(dev);
            goto fail;
        }
        pipe->slotid = slotid;
    }
    else
    {
        struct xhci_pipe *defpipe = container_of(
            usbdev->defpipe, struct xhci_pipe, pipe);
        pipe->slotid = defpipe->slotid;
        // Send configure command.
        int cc = xhci_cmd_configure_endpoint(xhci, pipe->slotid, in);
        if (cc != CC_SUCCESS)
        {
            goto fail;
        }
    }
    free(in);
    return &pipe->pipe;

fail:
    free(pipe->buf);
    free(pipe);
    free(in);
    return NULL;
}

struct usb_pipe *
xhci_realloc_pipe(struct usbdevice_s *usbdev, struct usb_pipe *upipe, struct usb_endpoint_descriptor *epdesc)
{
    if (!epdesc)
    {
        usb_add_freelist(upipe);
        return NULL;
    }
    if (!upipe)
        return xhci_alloc_pipe(usbdev, epdesc);
    uint8_t eptype = epdesc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
    int oldmaxpacket = upipe->maxpacket;
    usb_desc2pipe(upipe, usbdev, epdesc);
    struct xhci_pipe *pipe = container_of(upipe, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(
        pipe->pipe.cntl, struct usb_xhci_s, usb);
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
    if (cc != CC_SUCCESS)
    {
    }
    free(in);

    return upipe;
}

// Submit a USB "setup" message request to the pipe's ring
static void xhci_xfer_setup(struct xhci_pipe *pipe, int dir, void *cmd, void *data, int datalen)
{
    struct usb_xhci_s *xhci = container_of(
        pipe->pipe.cntl, struct usb_xhci_s, usb);
    xhci_trb_queue(&pipe->reqs, cmd, USB_CONTROL_SETUP_SIZE, (TR_SETUP << 10) | TRB_TR_IDT | ((datalen ? (dir ? 3 : 2) : 0) << 16));
    if (datalen)
        xhci_trb_queue(&pipe->reqs, data, datalen, (TR_DATA << 10) | ((dir ? 1 : 0) << 16));
    xhci_trb_queue(&pipe->reqs, NULL, 0, (TR_STATUS << 10) | TRB_TR_IOC | ((dir ? 0 : 1) << 16));
    xhci_doorbell(xhci, pipe->slotid, pipe->epid);
}

// Submit a USB transfer request to the pipe's ring
static void xhci_xfer_normal(struct xhci_pipe *pipe,
                             void *data, int datalen)
{
    struct usb_xhci_s *xhci = container_of(
        pipe->pipe.cntl, struct usb_xhci_s, usb);
    xhci_trb_queue(&pipe->reqs, data, datalen, (TR_NORMAL << 10) | TRB_TR_IOC);
    xhci_doorbell(xhci, pipe->slotid, pipe->epid);
}

int xhci_send_pipe(struct usb_pipe *p, int dir, const void *cmd, void *data, int datalen)
{
    struct xhci_pipe *pipe = container_of(p, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(pipe->pipe.cntl, struct usb_xhci_s, usb);

    if (cmd)
    {
        const struct usb_ctrlrequest *req = cmd;
        if (req->bRequest == USB_REQ_SET_ADDRESS)
            // Set address command sent during xhci_alloc_pipe.
            return 0;
        xhci_xfer_setup(pipe, dir, (void *)req, data, datalen);
    }
    else
    {
        xhci_xfer_normal(pipe, data, datalen);
    }

    int cc = xhci_event_wait(xhci, &pipe->reqs, usb_xfer_time(p, datalen));
    if (cc != CC_SUCCESS)
    {
        return -1;
    }

    return 0;
}

int xhci_poll_intr(struct usb_pipe *p, void *data)
{
    struct xhci_pipe *pipe = container_of(p, struct xhci_pipe, pipe);
    struct usb_xhci_s *xhci = container_of(pipe->pipe.cntl, struct usb_xhci_s, usb);
    uint32_t len = pipe->pipe.maxpacket;
    void *buf = pipe->buf;
    int bufused = pipe->bufused;

    if (!bufused)
    {
        xhci_xfer_normal(pipe, buf, len);
        bufused = 1;
        pipe->bufused = bufused;
        return -1;
    }

    xhci_process_events(xhci);
    if (xhci_ring_busy(&pipe->reqs))
        return -1;
    memcpy(data, buf, len);
    xhci_xfer_normal(pipe, buf, len);
    return 0;
}

int xhci_probe(pci_device_t *dev, uint32_t vendor_device_id)
{
    printf("Found XHCI controller.\n");

    if (dev->vendor_id == 0x8086 && dev->device_id == 0x1e31)
    {
#define USB3_PSSEN 0xd0
#define XUSB2PR 0xd8
        printf("Found Intel XHCI controller.\n");

        dev->op->write(dev->bus, dev->slot, dev->func, dev->segment, USB3_PSSEN, 0xffffffff);
        dev->op->write(dev->bus, dev->slot, dev->func, dev->segment, XUSB2PR, 0xffffffff);
    }

    uint64_t mmio_phys = dev->bars[0].address;
    void *baseaddr = (void *)phys_to_virt(mmio_phys);

    map_page_range(get_current_page_dir(false), (uint64_t)baseaddr, mmio_phys, dev->bars[0].size, PT_FLAG_R | PT_FLAG_W);

    struct usb_xhci_s *xhci = xhci_controller_setup(baseaddr);

    if (!xhci)
        return -1;

    int ret = configure_xhci(xhci);
    if (ret)
        return ret;

    dev->desc = xhci;

    return 0;
}

void xhci_remove(pci_device_t *dev)
{
}

void xhci_shutdown(pci_device_t *dev)
{
}

pci_driver_t xhci_hcd_driver = {
    .name = "xhci_hcd",
    .class_id = 0x000C0330,
    .vendor_device_id = 0x00000000,
    .probe = xhci_probe,
    .remove = xhci_remove,
    .shutdown = xhci_shutdown,
};

__attribute__((visibility("default"))) int dlmain()
{
    regist_pci_driver(&xhci_hcd_driver);

    return 0;
}
