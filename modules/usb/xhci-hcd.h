#pragma once

#include <libs/aether/usb.h>
#include <libs/aether/mm.h>

struct usbdevice_s;
struct usb_endpoint_descriptor;
struct usb_pipe;

struct usb_pipe *xhci_realloc_pipe(struct usbdevice_s *usbdev,
                                   struct usb_pipe *upipe,
                                   struct usb_endpoint_descriptor *epdesc);
int xhci_send_pipe(struct usb_pipe *p, int dir, const void *cmd, void *data,
                   int datasize);
int xhci_poll_intr(struct usb_pipe *p, void *data);

// register interface

// capabilities
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

// extended capabilities
struct xhci_xcap {
    uint32_t cap;
    uint32_t data[];
} __attribute__((packed));

// operational registers
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

// port registers
struct xhci_pr {
    uint32_t portsc;
    uint32_t portpmsc;
    uint32_t portli;
    uint32_t reserved_01;
} __attribute__((packed));

// doorbell registers
struct xhci_db {
    uint32_t doorbell;
} __attribute__((packed));

// runtime registers
struct xhci_rts {
    uint32_t mfindex;
} __attribute__((packed));

// interrupter registers
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

// --------------------------------------------------------------
// memory data structs

// slot context
struct xhci_slotctx {
    uint32_t ctx[4];
    uint32_t reserved_01[4];
} __attribute__((packed));

// endpoint context
struct xhci_epctx {
    uint32_t ctx[2];
    uint32_t deq_low;
    uint32_t deq_high;
    uint32_t length;
    uint32_t reserved_01[3];
} __attribute__((packed));

// device context array element
struct xhci_devlist {
    uint32_t ptr_low;
    uint32_t ptr_high;
} __attribute__((packed));

// input context
struct xhci_inctx {
    uint32_t del;
    uint32_t add;
    uint32_t reserved_01[6];
} __attribute__((packed));

// transfer block (ring element)
struct xhci_trb {
    uint32_t ptr_low;
    uint32_t ptr_high;
    uint32_t status;
    uint32_t control;
} __attribute__((packed));

// event ring segment
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
