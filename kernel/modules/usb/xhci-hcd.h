#pragma once

#include <libs/aether/stdio.h>
#include <libs/aether/mm.h>
#include <libs/aether/pci.h>
#include <libs/aether/time.h>
#include <libs/aether/task.h>

#define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))

#define GET_LOW(var) (var)
#define SET_LOW(var, val) \
    do                    \
    {                     \
        (var) = (val);    \
    } while (0)
#define LOWFLAT2LOW(var) (var)
#define GET_LOWFLAT(var) GET_LOW(*LOWFLAT2LOW(&(var)))
#define SET_LOWFLAT(var, val) SET_LOW(*LOWFLAT2LOW(&(var)), (val))

struct usbdevice_s;
struct usb_endpoint_descriptor;
struct usb_pipe;

// --------------------------------------------------------------

// usb-xhci.c
struct usb_pipe *xhci_realloc_pipe(struct usbdevice_s *usbdev, struct usb_pipe *upipe, struct usb_endpoint_descriptor *epdesc);
int xhci_send_pipe(struct usb_pipe *p, int dir, const void *cmd, void *data, int datasize);
int xhci_poll_intr(struct usb_pipe *p, void *data);

// --------------------------------------------------------------
// register interface

// capabilities
struct xhci_caps
{
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
struct xhci_xcap
{
    uint32_t cap;
    uint32_t data[];
} __attribute__((packed));

// operational registers
struct xhci_op
{
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
struct xhci_pr
{
    uint32_t portsc;
    uint32_t portpmsc;
    uint32_t portli;
    uint32_t reserved_01;
} __attribute__((packed));

// doorbell registers
struct xhci_db
{
    uint32_t doorbell;
} __attribute__((packed));

// runtime registers
struct xhci_rts
{
    uint32_t mfindex;
} __attribute__((packed));

// interrupter registers
struct xhci_ir
{
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
struct xhci_slotctx
{
    uint32_t ctx[4];
    uint32_t reserved_01[4];
} __attribute__((packed));

// endpoint context
struct xhci_epctx
{
    uint32_t ctx[2];
    uint32_t deq_low;
    uint32_t deq_high;
    uint32_t length;
    uint32_t reserved_01[3];
} __attribute__((packed));

// device context array element
struct xhci_devlist
{
    uint32_t ptr_low;
    uint32_t ptr_high;
} __attribute__((packed));

// input context
struct xhci_inctx
{
    uint32_t del;
    uint32_t add;
    uint32_t reserved_01[6];
} __attribute__((packed));

// transfer block (ring element)
struct xhci_trb
{
    uint32_t ptr_low;
    uint32_t ptr_high;
    uint32_t status;
    uint32_t control;
} __attribute__((packed));

// event ring segment
struct xhci_er_seg
{
    uint32_t ptr_low;
    uint32_t ptr_high;
    uint32_t size;
    uint32_t reserved_01;
} __attribute__((packed));

int xhci_probe(pci_device_t *dev, uint32_t vendor_device_id);

void xhci_remove(pci_device_t *dev);
void xhci_shutdown(pci_device_t *dev);
