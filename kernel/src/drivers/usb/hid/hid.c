#include <drivers/usb/hid/hid.h>
#include <drivers/usb/hid/kbd.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>
#include <task/task.h>

#define MAX_KBD_EVENT 16

#define HID_REQ_GET_REPORT 0x01
#define HID_REQ_GET_IDLE 0x02
#define HID_REQ_GET_PROTOCOL 0x03
#define HID_REQ_SET_REPORT 0x09
#define HID_REQ_SET_IDLE 0x0A
#define HID_REQ_SET_PROTOCOL 0x0B

#define HID_SET_PROTOCOL_BOOT 0
#define HID_SET_PROTOCOL_REPORT 1

typedef struct _HID_STANDARD_KEYEVENT
{
    uint8_t MOD;
    uint8_t RSV;
    uint8_t KEY[6];
} HID_STANDARD_KEYEVENT;

USB_PIPE *KEYBOARD_PIPE = 0;
HID_STANDARD_KEYEVENT *KEYEVENT0 = NULL;
HID_STANDARD_KEYEVENT *KEYEVENT1 = NULL;
uint16_t KEYPRESS[16];

void usb_keyboard_event()
{
    printk("USB kernel thread running...\n");

    while (true)
    {
        if (KEYBOARD_PIPE)
        {
            // printk("USB KEYBOARD EVENT\n");
            // Assume to xHCI pipe
            if (!KEYEVENT1->RSV)
            {
                KEYEVENT1->RSV = 1;
                for (uint32_t i = 0; i < 6; i++)
                {
                    if (KEYEVENT0->KEY[i])
                    {
                        uint8_t cod = KEYEVENT0->KEY[i];
                        uint8_t idx = cod >> 4;
                        uint16_t msk = ~(1 << (cod & 0xF));
                        int up = 1;
                        for (uint32_t j = 0; (j < 6) && up; j++)
                        {
                            if (cod == KEYEVENT1->KEY[j])
                            {
                                up = 0;
                            }
                        }
                        if (up)
                        {
                            KEYPRESS[idx] &= msk;
                        }
                    }
                }
                for (uint32_t i = 0; i < 6; i++)
                {
                    if (KEYEVENT1->KEY[i])
                    {
                        uint8_t cod = KEYEVENT1->KEY[i];
                        uint8_t idx = cod >> 4;
                        uint16_t msk = (1 << (cod & 0xF));
                        if (!(KEYPRESS[idx] & msk))
                        {
                            KeyEvent(&KEY_RING, cod);
                        }
                        KEYPRESS[idx] |= msk;
                    }
                }

                memcpy(KEYEVENT0, KEYEVENT1, sizeof(HID_STANDARD_KEYEVENT));
            }

            XHCI_PIPE *xpipe = (XHCI_PIPE *)KEYBOARD_PIPE;
            if (xpipe->RING.NID == xpipe->RING.EID)
            {
                KEYBOARD_PIPE->CTRL->XFER(KEYBOARD_PIPE, 0, KEYEVENT1, sizeof(HID_STANDARD_KEYEVENT), 1);
            }
        }

        arch_enable_interrupt();

        arch_pause();
    }
}

uint32_t ConfigureKeyboard(USB_COMMON *usbdev, USB_ENDPOINT *epdesc)
{
    if (KEYBOARD_PIPE)
        return -1; // Only enable first found keyboard

    if (epdesc->MPS < sizeof(HID_STANDARD_KEYEVENT) || epdesc->MPS > MAX_KBD_EVENT)
    {
        printk("USB KEYBOARD MAX PACKET SIZE=%#06x\n", epdesc->MPS);
        return -1;
    }

    // SET PROTOCOL
    USB_DEVICE_REQUEST req;
    req.T = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    req.C = HID_REQ_SET_PROTOCOL;
    req.V = HID_SET_PROTOCOL_BOOT;
    req.I = usbdev->IFC->IN;
    req.L = 0;
    int cc = usbdev->CTRL->XFER(usbdev->PIPE, &req, 0, 0, 0);
    if (cc)
    {
        printk("CANNOT SET PROTOCOL %#04x\n", cc);
        return cc;
    }

    // SET IDLE 4ms
    req.T = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    req.C = HID_REQ_SET_IDLE;
    req.V = 1 << 8;
    req.I = 0;
    req.L = 0;
    cc = usbdev->CTRL->XFER(usbdev->PIPE, &req, 0, 0, 0);
    if (cc)
    {
        printk("CANNOT SET IDLE %#04x\n", cc);
        return cc;
    }

    CreateKeyEventRing(&KEY_RING);

    KEYBOARD_PIPE = usbdev->CTRL->CPIP(usbdev, 0, epdesc);
    if (!KEYBOARD_PIPE)
    {
        printk("CANNOT CREATE PIPE\n");
        return -1;
    }

    KEYEVENT0 = alloc_frames_bytes(sizeof(HID_STANDARD_KEYEVENT));
    KEYEVENT1 = alloc_frames_bytes(sizeof(HID_STANDARD_KEYEVENT));
    memset(KEYEVENT0, 0, sizeof(HID_STANDARD_KEYEVENT));
    memset(KEYEVENT1, 0, sizeof(HID_STANDARD_KEYEVENT));
    KEYEVENT1->RSV = 1;

    task_create("USB KBD THREAD", usb_keyboard_event);

    return 0;
}
uint32_t ConfigureHID(USB_COMMON *usbdev)
{
    USB_INTERFACE *iface = usbdev->IFC;
    if (iface->IS != USB_INTERFACE_SUBCLASS_BOOT)
    {
        // printk("NOT A BOOT DEVICE\n");
        return -1;
    }

    USB_ENDPOINT *epdesc = USBSearchEndpoint(usbdev, USB_ENDPOINT_XFER_INT, USB_DIR_IN);
    if (!epdesc)
    {
        printk("NO USB HID INTEERRUPT IN\n");
        return -1;
    }
    if (iface->IP == USB_INTERFACE_PROTOCOL_KEYBOARD)
    {
        return ConfigureKeyboard(usbdev, epdesc);
    }
    else if (iface->IP == USB_INTERFACE_PROTOCOL_MOUSE)
    {
        return -1; // todo: ConfigureMouse
    }

    return -1;
}
