#pragma once

#include <drivers/usb/usb.h>
#include <mm/mm.h>

typedef struct xhci_caps xhci_caps_t;
typedef struct xhci_xcap xhci_xcap_t;
typedef struct xhci_op xhci_op_t;
typedef struct xhci_pr xhci_port_regs_t;
typedef struct xhci_db xhci_db_t;
typedef struct xhci_rts xhci_runtime_regs_t;
typedef struct xhci_ir xhci_interrupter_regs_t;
typedef struct xhci_slotctx xhci_slot_ctx_t;
typedef struct xhci_epctx xhci_ep_ctx_t;
typedef struct xhci_devlist xhci_dev_ctx_entry_t;
typedef struct xhci_inctx xhci_input_ctx_t;
typedef struct xhci_trb xhci_trb_t;
typedef struct xhci_er_seg xhci_event_ring_seg_t;

usb_pipe_t *xhci_realloc_pipe(usb_device_t *usbdev, usb_pipe_t *upipe,
                              usb_endpoint_descriptor_t *epdesc,
                              usb_super_speed_endpoint_descriptor_t *ss_epdesc);
int xhci_send_pipe(usb_pipe_t *pipe, int dir, const void *cmd, void *data,
                   int datasize, uint64_t timeout_ns);
int xhci_send_intr_pipe(usb_pipe_t *pipe, void *buf, int len, intr_xfer_cb cb,
                        void *user_data);

struct xhci_caps {
    uint8_t caplength;
    uint8_t reserved_01;
    uint16_t hciversion;
    uint32_t hcsparams1;
    uint32_t hcsparams2;
    uint32_t hcsparams3;
    uint32_t hccparams;
    uint32_t dboff;
    uint32_t rtsoff;
} __attribute__((packed));

struct xhci_xcap {
    uint32_t cap;
    uint32_t data[];
} __attribute__((packed));

struct xhci_op {
    uint32_t usbcmd;
    uint32_t usbsts;
    uint32_t pagesize;
    uint32_t reserved_01[2];
    uint32_t dnctl;
    uint32_t crcr_low;
    uint32_t crcr_high;
    uint32_t reserved_02[4];
    uint32_t dcbaap_low;
    uint32_t dcbaap_high;
    uint32_t config;
} __attribute__((packed));

struct xhci_pr {
    uint32_t portsc;
    uint32_t portpmsc;
    uint32_t portli;
    uint32_t reserved_01;
} __attribute__((packed));

struct xhci_db {
    uint32_t doorbell;
} __attribute__((packed));

struct xhci_rts {
    uint32_t mfindex;
} __attribute__((packed));

struct xhci_ir {
    uint32_t iman;
    uint32_t imod;
    uint32_t erstsz;
    uint32_t reserved_01;
    uint32_t erstba_low;
    uint32_t erstba_high;
    uint32_t erdp_low;
    uint32_t erdp_high;
} __attribute__((packed));

struct xhci_slotctx {
    uint32_t ctx[4];
    uint32_t reserved_01[4];
} __attribute__((packed));

struct xhci_epctx {
    uint32_t ctx[2];
    uint32_t deq_low;
    uint32_t deq_high;
    uint32_t length;
    uint32_t reserved_01[3];
} __attribute__((packed));

struct xhci_devlist {
    uint32_t ptr_low;
    uint32_t ptr_high;
} __attribute__((packed));

struct xhci_inctx {
    uint32_t del;
    uint32_t add;
    uint32_t reserved_01[6];
} __attribute__((packed));

struct xhci_trb {
    uint32_t ptr_low;
    uint32_t ptr_high;
    uint32_t status;
    uint32_t control;
} __attribute__((packed));

struct xhci_er_seg {
    uint32_t ptr_low;
    uint32_t ptr_high;
    uint32_t size;
    uint32_t reserved_01;
} __attribute__((packed));

static inline void writel(void *addr, uint32_t val) {
    dma_wmb();
    *(volatile uint32_t *)addr = val;
    dma_wmb();
}

static inline void writew(void *addr, uint16_t val) {
    dma_wmb();
    *(volatile uint16_t *)addr = val;
    dma_wmb();
}

static inline void writeb(void *addr, uint8_t val) {
    dma_wmb();
    *(volatile uint8_t *)addr = val;
    dma_wmb();
}

static inline uint64_t readq(const void *addr) {
    dma_rmb();
    uint64_t val = *(volatile const uint64_t *)addr;
    dma_rmb();
    return val;
}

static inline uint32_t readl(const void *addr) {
    dma_rmb();
    uint32_t val = *(volatile const uint32_t *)addr;
    dma_rmb();
    return val;
}

static inline uint16_t readw(const void *addr) {
    dma_rmb();
    uint16_t val = *(volatile const uint16_t *)addr;
    dma_rmb();
    return val;
}

static inline uint8_t readb(const void *addr) {
    dma_rmb();
    uint8_t val = *(volatile const uint8_t *)addr;
    dma_rmb();
    return val;
}
