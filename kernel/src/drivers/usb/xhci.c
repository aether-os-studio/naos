#include <drivers/usb/xhci.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <task/task.h>

const char MSG0901[] = "ERROR:XHCI PAGE SIZE ";
const char MSG0902[] = "ERROR:XHCI WAIT TIMEOUT\n";
const char MSG0903[] = "UNKNOWN EVENT TYPE ";
const uint32_t SPEED_XHCI[16] =
    {
        -1,
        USB_FULLSPEED,
        USB_LOWSPEED,
        USB_HIGHSPEED,
        USB_SUPERSPEED,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
};
USB_HUB_OPERATION XHCI_OPERARTION;

void xhci_init()
{
    pci_device_t *devs[16];
    uint32_t xhci_dev_num;

    pci_find_class(devs, &xhci_dev_num, 0x0C0330);

    if (xhci_dev_num == 0)
    {
        printk("No XHCI controller found\n");
        return;
    }

    // for (int i = 0; i < xhci_dev_num; i++)
    for (int i = 0; i < 1; i++)
    {
        SetupXHCIControllerPCI(devs[i]);
    }
}

void SetupXHCIControllerPCI(pci_device_t *dvc)
{
    XHCI_OPERARTION.DTC = XHCIHUBDetect;
    XHCI_OPERARTION.RST = XHCIHUBReset;
    XHCI_OPERARTION.DCC = XHCIHUBDisconnect;

    uint64_t virt = phys_to_virt(dvc->bars[0].address);
    map_page_range(get_current_page_dir(false), virt, dvc->bars[0].address, dvc->bars[0].size, PT_FLAG_R | PT_FLAG_W);

    uint32_t cmd = dvc->op->read(dvc->bus, dvc->slot, dvc->func, dvc->segment, 0x04);
    cmd |= 0x6;
    dvc->op->write(dvc->bus, dvc->slot, dvc->func, dvc->segment, 0x04, cmd);

    XHCI_CONTROLLER *controller = SetupXHCIController(virt);
    if (!controller)
    {
        return;
    }

    USB_CTRL = (USB_CONTROLLER *)controller;

    if (ConfigureXHCI(controller))
    {
        free(controller);
    }
}

XHCI_CONTROLLER *SetupXHCIController(uint64_t bar)
{
    XHCI_CONTROLLER *controller = (XHCI_CONTROLLER *)malloc(sizeof(XHCI_CONTROLLER));
    memset(controller, 0, sizeof(XHCI_CONTROLLER));
    controller->USB.TYPE = USB_TYPE_XHCI;
    controller->CR = (XHCI_CAPABILITY *)(bar);
    controller->OR = (XHCI_OPERATIONAL *)(bar + controller->CR->CL);
    controller->PR = (XHCI_PORT *)(bar + controller->CR->CL + 0x400);
    controller->RR = (XHCI_RUNTIME *)(bar + controller->CR->RRSO);
    controller->DR = (uint32_t *)(bar + controller->CR->DBO);

    uint32_t pageSize = controller->OR->PS;
    if (pageSize != 1)
    {
        printk(MSG0901);
        printk("%#010x\n", pageSize, 8);
        free(controller);
        return 0;
    }

    uint32_t sp1 = controller->CR->SP1;
    uint32_t cp1 = controller->CR->CP1;
    controller->SN = (sp1 >> 0) & 0xFF;
    controller->IN = (sp1 >> 8) & 0x7FF;
    controller->PN = (sp1 >> 24) & 0xFF;
    controller->XEC = ((cp1 >> 16) & 0xFFFF) << 2;
    controller->CSZ = ((cp1 >> 2) & 0x0001);

    /*
    if (controller->XEC)
    {
        uint32_t off = ~0;
        uint64_t addr = bar + controller->XEC;
        while (off)
        {
            XHCI_XCAPABILITY *xcap = (XHCI_XCAPABILITY *) addr;
            uint32_t cap = xcap->CAP;
            if ((cap & 0xFF) == 0x02)
            {
                uint64_t name = xcap->DATA[0];
                uint32_t ports = xcap->DATA[1];
                uint8_t major = (cap >> 24) & 0xFF;
                uint8_t minor = (cap >> 16) & 0xFF;
                uint8_t count = (ports >> 8) & 0xFF;
                uint8_t start = (ports >> 0) & 0xFF;
                uint64_t txt = 0x2049434858; // XHCI
                printk((char *) &txt);
                printk((char *) &name);
                OUTCHAR(' ');
                PRINTRAX(major, 1);
                OUTCHAR('.');
                PRINTRAX(minor, 2);
                OUTCHAR(' ');
                PRINTRAX(count, 2);
                txt = 0x2B2820;// (+
                printk((char *) &txt);
                PRINTRAX(start - 1, 2);
                txt = 0x2029; // )
                printk((char *) &txt);
                PRINTRAX(ports >> 16, 4);
                LINEFEED();
            }
            else
            {
                uint64_t txt = 0x2049434858; // XHCI
                printk((char *) &txt);
                txt = 0x2050414358; // XCAP
                printk((char *) &txt);
                PRINTRAX(cap & 0xFF, 2);
                txt = 0x204020; // @
                printk((char *) &txt);
                PRINTRAX(addr, 16);
                LINEFEED();
            }
            off = (cap >> 8) & 0xFF;
            addr += (uint64_t) off << 2;
        }
    }
    */

    controller->USB.CPIP = XHCICreatePipe;
    controller->USB.XFER = XHCITransfer;

    return controller;
}

uint32_t ConfigureXHCI(XHCI_CONTROLLER *controller)
{
    uint64_t physicalAddress = phys_to_virt(alloc_frames(1));
    memset((void *)physicalAddress, 0, DEFAULT_PAGE_SIZE);
    controller->DVC = (uint64_t *)(physicalAddress + 0x000);
    controller->SEG = (XHCI_RING_SEGMENT *)(physicalAddress + 0x800);
    XHCICreateTransferRing(&controller->CMD);
    XHCICreateTransferRing(&controller->EVT);

    // Reset controller
    /*
    uint32_t reg = controller->OR->CMD;
    reg &= ~XHCI_CMD_INTE;
    reg &= ~XHCI_CMD_HSEE;
    reg &= ~XHCI_CMD_EWE;
    reg &= ~XHCI_CMD_RS;
    controller->OR->CMD = reg;
    while (!(controller->OR->STS & XHCI_STS_HCH)) arch_pause();
    controller->OR->CMD |= XHCI_CMD_HCRST;
    while (controller->OR->CMD & XHCI_CMD_HCRST) arch_pause();
    while (controller->OR->STS & XHCI_STS_CNR) arch_pause();
    */
    uint32_t reg = controller->OR->CMD;
    if (reg & XHCI_CMD_RS)
    {
        reg &= ~XHCI_CMD_RS;
        controller->OR->CMD = reg;
        while (!(controller->OR->STS & XHCI_STS_HCH))
            arch_pause();
    }
    controller->OR->CMD = XHCI_CMD_HCRST;
    while (controller->OR->CMD & XHCI_CMD_HCRST)
        arch_pause();
    while (controller->OR->STS & XHCI_STS_CNR)
        arch_pause();

    controller->OR->CFG = controller->SN;
    controller->CMD.CCS = 1;
    controller->OR->CRC = virt_to_phys((uint64_t)controller->CMD.RING) | 1;
    controller->OR->DCA = virt_to_phys((uint64_t)controller->DVC);

    controller->SEG->A = virt_to_phys((uint64_t)controller->EVT.RING);
    controller->SEG->S = XHCI_RING_ITEMS;

    controller->EVT.CCS = 1;
    controller->RR->IR[0].IMOD = 0;
    controller->RR->IR[0].IMAN |= 2; // Interrupt Enable
    controller->RR->IR[0].TS = 1;
    controller->RR->IR[0].ERS = virt_to_phys((uint64_t)controller->SEG);
    controller->RR->IR[0].ERD = virt_to_phys((uint64_t)controller->EVT.RING);

    reg = controller->CR->SP2;
    uint32_t spb = (reg >> 21 & 0x1F) << 5 | reg >> 27;
    if (spb)
    {
        /*
        printk("CREATE SCRATCHPAD ");
        PRINTRAX(spb, 3);
        LINEFEED();
        */
        uint64_t pageAddress = 0;
        uint64_t *spba = 0;
        spba = (uint64_t *)phys_to_virt(alloc_frames(1));
        memset(spba, 0, DEFAULT_PAGE_SIZE);
        for (uint32_t i = 0; i < spb; i++)
        {
            pageAddress = alloc_frames(1);
            memset((void *)phys_to_virt(pageAddress), 0, DEFAULT_PAGE_SIZE);
            spba[i] = pageAddress;
        }
        controller->DVC[0] = virt_to_phys((uint64_t)spba);
    }

    controller->OR->CMD |= XHCI_CMD_INTE;
    controller->OR->CMD |= XHCI_CMD_RS;

    // Find devices
    arch_pause();
    arch_pause();
    USB_HUB *hub = &controller->USB.RH;
    hub->CTRL = &controller->USB;
    hub->PC = controller->PN;
    hub->OP = &XHCI_OPERARTION;

    int count = USBEnumerate(hub);
    // xhci_free_pipes
    // if (count)
    //     return 0; // Success

    // // No devices found - shutdown and free controller.
    // printk("XHCI NO DEVICE FOUND\n");
    // controller->OR->CMD &= ~XHCI_CMD_RS;
    // while (!(controller->OR->STS & XHCI_STS_HCH))
    //     arch_pause();

    free_frames(virt_to_phys(physicalAddress), 1);
    return 0;
}

void XHCIQueueTRB(XHCI_TRANSFER_RING *ring, XHCI_TRANSFER_BLOCK *block)
{
    if (ring->NID >= XHCI_RING_ITEMS - 1)
    {
        XHCI_TRB_LINK trb;
        memset(&trb, 0, sizeof(XHCI_TRB_LINK));
        trb.RSP = virt_to_phys((uint64_t)ring->RING) >> 4;
        trb.TYPE = TRB_LINK;
        trb.TC = 1;
        XHCICopyTRB(ring, &trb.TRB);
        ring->NID = 0;
        ring->CCS ^= 1;
    }
    XHCICopyTRB(ring, block);
    ring->NID++;
}
void XHCICopyTRB(XHCI_TRANSFER_RING *ring, XHCI_TRANSFER_BLOCK *element)
{
    XHCI_TRANSFER_BLOCK *dst = ring->RING + ring->NID;
    dst->DATA[0] = element->DATA[0];
    dst->DATA[1] = element->DATA[1];
    dst->DATA[2] = element->DATA[2];
    dst->DATA[3] = element->DATA[3] | ring->CCS;
}
void XHCIDoorbell(XHCI_CONTROLLER *controller, uint32_t slot, uint32_t value)
{
    controller->DR[slot] = value;
}

uint32_t XHCIProcessEvent(XHCI_CONTROLLER *controller)
{
    // Check for event
    XHCI_TRANSFER_RING *event = &controller->EVT;
    uint32_t nid = event->NID;
    XHCI_TRANSFER_BLOCK *trb = event->RING + nid;
    if (trb->TYPE == 0)
        return 0;
    if ((trb->C != event->CCS))
        return 0;

    // Process event
    uint32_t eventType = trb->TYPE;
    switch (eventType)
    {
    case TRB_TRANSFER:
    case TRB_COMMAND_COMPLETE:
    {
        XHCI_TRB_COMMAND_COMPLETION *cc = (XHCI_TRB_COMMAND_COMPLETION *)trb;
        uint64_t ctp = phys_to_virt((uint64_t)cc->CTP);
        XHCI_TRANSFER_BLOCK *firstTRB = (XHCI_TRANSFER_BLOCK *)((ctp >> 12) << 12);
        XHCI_TRB_TRANSFER_RING *ringTRB = (XHCI_TRB_TRANSFER_RING *)(firstTRB + XHCI_RING_ITEMS);
        XHCI_TRANSFER_RING *ring = (XHCI_TRANSFER_RING *)phys_to_virt(ringTRB->RING);
        uint32_t eid = ((cc->CTP & 0xFF0) >> 4) + 1;
        memcpy(&ring->EVT, trb, sizeof(XHCI_TRANSFER_BLOCK));
        ring->EID = eid;

        break;
    }
    case TRB_PORT_STATUS_CHANGE:
    {
        uint32_t port = ((trb->DATA[0] >> 24) & 0xFF) - 1;
        uint32_t psc = controller->PR[port].PSC;
        // int count = USBEnumerate(&controller->USB.RH);
        // uint32_t pcl = (((psc & ~(XHCI_PORTSC_PED | XHCI_PORTSC_PR)) & ~(0x1E0)) | (0x20));
        uint32_t pcl = (((psc & ~(XHCI_PORTSC_PED | XHCI_PORTSC_PR)) & ~(0xF << 5)) | (1 << 5));
        controller->PR[port].PSC = pcl;
        break;
    }
    default:
    {
        printk(MSG0903);
        printk("%#04x", eventType, 2);
        printk("\n");
    }
    }
    memset(trb, 0, sizeof(XHCI_TRANSFER_BLOCK));

    // Move ring index, notify xhci
    nid++;
    if (nid == XHCI_RING_ITEMS)
    {
        nid = 0;
        event->CCS ^= 1;
    }
    event->NID = nid;
    controller->RR->IR[0].ERD = virt_to_phys((uint64_t)(event->RING + event->NID));
    return 1;
}
uint32_t XHCIWaitCompletion(XHCI_CONTROLLER *controller, XHCI_TRANSFER_RING *ring)
{
    while (ring->EID != ring->NID)
    {
        while (XHCIProcessEvent(controller))
            arch_pause();

        arch_pause();
    }
    return ring->EVT.DATA[2] >> 24;
}
uint32_t XHCICommand(XHCI_CONTROLLER *controller, XHCI_TRANSFER_BLOCK *trb)
{
    XHCIQueueTRB(&controller->CMD, trb);
    controller->DR[0] = 0;
    return XHCIWaitCompletion(controller, &controller->CMD);
}
uint32_t XHCIHUBDetect(USB_HUB *hub, uint32_t port)
{
    XHCI_CONTROLLER *controller = (XHCI_CONTROLLER *)hub->CTRL;
    return (controller->PR[port].PSC & XHCI_PORTSC_CCS);
}
uint32_t XHCIHUBReset(USB_HUB *hub, uint32_t port)
{
    XHCI_CONTROLLER *controller = (XHCI_CONTROLLER *)hub->CTRL;
    if (!(controller->PR[port].PSC & XHCI_PORTSC_CCS))
        return -1;

    switch (((controller->PR[port].PSC >> 5) & 0xF))
    {
    case PLS_U0:
    {
        // A USB 3 port - controller automatically performs reset
        break;
    }
    case PLS_POLLING:
    {
        // A USB 2 port - perform device reset
        controller->PR[port].PSC |= XHCI_PORTSC_PR;
        break;
    }
    default:
        return -1;
    }

    // Wait for device to complete reset and be enabled
    arch_pause();
    arch_pause();
    arch_pause();
    while (1)
    {
        uint32_t psc = controller->PR[port].PSC;
        if (!(psc & XHCI_PORTSC_CCS))
        {
            // Device disconnected during reset
            return -1;
        }
        if (psc & XHCI_PORTSC_PED)
        {
            // Reset complete
            break;
        }
        arch_pause();
    }
    /*
    uint64_t txt = 0x2049434858; // XHCI
    printk((char *) &txt);
    txt = 0x20425355; // USB
    printk((char *) &txt);
    PRINTRAX(port, 2);
    txt = 0x2044505320;
    printk((char *) &txt);
    PRINTRAX((controller->PR[port].PSC >> 10) & 0xF, 1);
    if (controller->PR[port].PSC & XHCI_PORTSC_PED)
    {
        txt = 0x4E4520; // EN
        printk((char *) &txt);
    }
    if (controller->PR[port].PSC & XHCI_PORTSC_PP)
    {
        txt = 0x575020; // PW
        printk((char *) &txt);
    }
    LINEFEED();
    */
    return SPEED_XHCI[(controller->PR[port].PSC >> 10) & 0xF];
}
uint32_t XHCIHUBDisconnect(USB_HUB *hub, uint32_t port)
{
    // XXX - should turn the port power off.
    return 0;
}
uint64_t XHCICreateInputContext(USB_COMMON *usbdev, uint32_t maxepid)
{
    XHCI_CONTROLLER *controller = (XHCI_CONTROLLER *)usbdev->CTRL;
    uint64_t size = (sizeof(XHCI_INPUT_CONTROL_CONTEXT) << controller->CSZ) * 33;
    XHCI_INPUT_CONTROL_CONTEXT *icctx = (XHCI_INPUT_CONTROL_CONTEXT *)alloc_frames(1);
    icctx = (XHCI_INPUT_CONTROL_CONTEXT *)(phys_to_virt(icctx));
    memset(icctx, 0, size);

    XHCI_SLOT_CONTEXT *sctx = (XHCI_SLOT_CONTEXT *)(icctx + (1ULL << controller->CSZ));
    sctx->CE = maxepid;
    sctx->SPD = usbdev->SPD + 1;

    // Set high-speed hub flags.
    if (usbdev->HUB->DEVICE)
    {
        printk("SETUP HUB\n");
        USB_COMMON *hubdev = usbdev->HUB->DEVICE;
        if (usbdev->SPD == USB_LOWSPEED || usbdev->SPD == USB_FULLSPEED)
        {
            XHCI_PIPE *hpipe = (XHCI_PIPE *)hubdev->PIPE;
            if (hubdev->SPD == USB_HIGHSPEED)
            {
                sctx->TTID = hpipe->SID;
                sctx->TTP = usbdev->PORT + 1;
            }
            else
            {
                XHCI_SLOT_CONTEXT *hsctx = (XHCI_SLOT_CONTEXT *)phys_to_virt(controller->DVC[hpipe->SID]);
                sctx->TTID = hsctx->TTID;
                sctx->TTP = hsctx->TTP;
                sctx->TTT = hsctx->TTT;
                sctx->IT = hsctx->IT;
            }
        }
        uint32_t route = 0;
        while (usbdev->HUB->DEVICE)
        {
            route <<= 4;
            route |= (usbdev->PORT + 1) & 0xF;
            usbdev = usbdev->HUB->DEVICE;
        }
        sctx->RS = route;
    }

    sctx->RHPN = usbdev->PORT + 1;
    return (uint64_t)icctx;
}
USB_PIPE *XHCICreatePipe(USB_COMMON *common, USB_PIPE *upipe, USB_ENDPOINT *epdesc)
{
    if (!epdesc)
    {
        // Free
        if (upipe)
        {
            XHCI_PIPE *xpipe = (XHCI_PIPE *)upipe;
            free_frames(virt_to_phys((uint64_t)xpipe->RING.RING), 1);
            free(xpipe);
        }
        return 0;
    }
    if (!upipe)
    {
        XHCI_CONTROLLER *controller = (XHCI_CONTROLLER *)common->CTRL;
        uint8_t eptype = epdesc->AT & USB_ENDPOINT_XFER_TYPE;
        uint32_t epid = 1;
        if (epdesc->EA)
        {
            epid = (epdesc->EA & 0x0f) << 1;
            epid += (epdesc->EA & USB_DIR_IN) ? 1 : 0;
        }

        XHCI_PIPE *pipe = malloc(sizeof(XHCI_PIPE));
        memset(pipe, 0, sizeof(XHCI_PIPE));
        USBD2P(&pipe->USB, common, epdesc);
        pipe->EPID = epid;
        XHCICreateTransferRing(&pipe->RING);
        pipe->RING.CCS = 1;

        // Allocate input context and initialize endpoint info
        XHCI_INPUT_CONTROL_CONTEXT *icctx = (XHCI_INPUT_CONTROL_CONTEXT *)XHCICreateInputContext(common, epid);
        icctx->ADD = 1 | (1 << epid);
        XHCI_ENDPOINT_CONTEXT *epctx = (XHCI_ENDPOINT_CONTEXT *)(icctx + ((pipe->EPID + 1ULL) << controller->CSZ));

        if (eptype == USB_ENDPOINT_XFER_INT)
        {
            // usb_get_period
            /*
            uint32_t period = epdesc->ITV;
            if (common->SPD != USB_HIGHSPEED)
            {
                if (period)
                {
                    // BSR period, x
                    WORD x = period;
                    period = 0;
                    while (!(x & (1 << 15)))
                    {
                        x <<= 1;
                        period++;
                    }
                }
            }
            else
            {
                period = (period <= 4) ? 0 : (period - 4);
            }
            epctx->ITV = period + 3;
            */
            epctx->ITV = 3;
        }
        epctx->EPT = eptype;

        if (eptype == USB_ENDPOINT_XFER_CONTROL)
        {
            epctx->EPT = EP_CONTROL;
        }

        epctx->MPSZ = pipe->USB.MPS;
        epctx->TRDP = virt_to_phys((uint64_t)pipe->RING.RING) >> 4;
        epctx->DCS = 1;
        epctx->ATL = pipe->USB.MPS;

        if (pipe->EPID == 1)
        {
            if (common->HUB->DEVICE)
            {
                // printk("CONFIGURE HUB\n");
                // Make sure parent hub is configured.
                USB_HUB *hub = common->HUB;
                XHCI_SLOT_CONTEXT *hubsctx = phys_to_virt((XHCI_SLOT_CONTEXT *)controller->DVC[pipe->SID]);
                if (hubsctx->SS == 3) // Configured
                {
                    // Already configured
                    goto HUB_CONFIG_OVER;
                }
                XHCI_INPUT_CONTROL_CONTEXT *icctx = (XHCI_INPUT_CONTROL_CONTEXT *)XHCICreateInputContext(hub->DEVICE, 1);
                icctx->ADD = 1;
                XHCI_SLOT_CONTEXT *sctx = (XHCI_SLOT_CONTEXT *)(icctx + (1ULL << controller->CSZ));
                sctx->HUB = 1;
                sctx->PN = hub->PC;

                XHCI_TRB_CONFIGURE_ENDPOINT trb;
                memset(&trb, 0, sizeof(XHCI_TRB_CONFIGURE_ENDPOINT));
                trb.ICP = virt_to_phys((uint64_t)icctx);
                trb.TYPE = TRB_CONFIGURE_ENDPOINT;
                trb.SID = pipe->SID;
                uint32_t cc;
                if ((cc = XHCICommand(controller, &trb.TRB)) != 1)
                {
                    printk("CONFIGURE HUB FAILED %#04x\n", cc);
                    goto FAILED;
                }

            HUB_CONFIG_OVER:;
            }

            // Enable slot
            XHCI_TRB_ENABLE_SLOT trb00;
            memset(&trb00, 0, sizeof(XHCI_TRB_ENABLE_SLOT));
            trb00.TYPE = TRB_ENABLE_SLOT;
            uint32_t cc = XHCICommand(controller, &trb00.TRB);
            if (cc != 1)
            {
                printk("ENABLE SLOT FAILED %#04x\n", cc);
                goto FAILED;
            }
            uint32_t slot = controller->CMD.EVT.DATA[3] >> 24;

            uint32_t size = (sizeof(XHCI_SLOT_CONTEXT) << controller->CSZ) * 32;
            XHCI_SLOT_CONTEXT *dev = phys_to_virt((XHCI_SLOT_CONTEXT *)alloc_frames(1));
            memset(dev, 0, size);
            controller->DVC[slot] = virt_to_phys((uint64_t)dev);

            // Send SET_ADDRESS command
            // Send Address Device command
            XHCI_TRB_ADDRESS_DEVICE trb01;
            memset(&trb01, 0, sizeof(XHCI_TRB_ADDRESS_DEVICE));
            trb01.ICP = virt_to_phys((uint64_t)icctx) >> 4;
            trb01.TYPE = TRB_ADDRESS_DEVICE;
            trb01.SID = slot;
            cc = XHCICommand(controller, &trb01.TRB);
            if (cc != 1)
            {
                printk("ADDRESS DEVICE FAILED %#04x\n", cc);
                // Disable slot
                XHCI_TRB_DISABLE_SLOT trb02;
                memset(&trb02, 0, sizeof(XHCI_TRB_DISABLE_SLOT));
                trb02.TYPE = TRB_DISABLE_SLOT;
                trb02.SID = slot;
                cc = XHCICommand(controller, &trb02.TRB);
                if (cc != 1)
                {
                    printk("DISABLE SLOT FAILED %#04x", cc);
                    goto FAILED;
                }
                controller->DVC[slot] = 0;
                free_frames(virt_to_phys((uint64_t)dev), 1);
                goto FAILED;
            }
            pipe->SID = slot;
            free_frames(virt_to_phys((uint64_t)dev), 1);
        }
        else
        {
            XHCI_PIPE *defpipe = (XHCI_PIPE *)common->PIPE;
            pipe->SID = defpipe->SID;
            // Send configure command
            XHCI_TRB_CONFIGURE_ENDPOINT trb;
            memset(&trb, 0, sizeof(XHCI_TRB_CONFIGURE_ENDPOINT));
            trb.ICP = virt_to_phys((uint64_t)icctx);
            trb.TYPE = TRB_CONFIGURE_ENDPOINT;
            trb.SID = pipe->SID;
            uint32_t cc;
            if ((cc = XHCICommand(controller, &trb.TRB)) != 1)
            {
                printk("CONFIGURE ENDPOINT FAILED %#04x\n", cc);
                goto FAILED;
            }
        }
        free_frames(virt_to_phys((uint64_t)icctx), 1);
        return &pipe->USB;

    FAILED:;
        free_frames(virt_to_phys((uint64_t)icctx), 1);
        free_frames(virt_to_phys((uint64_t)pipe->RING.RING), 1);
        free(pipe);
        return 0;
    }
    uint8_t eptype = epdesc->AT & USB_ENDPOINT_XFER_TYPE;
    uint32_t oldmp = upipe->MPS;
    USBD2P(upipe, common, epdesc);
    XHCI_PIPE *pipe = (XHCI_PIPE *)upipe;
    XHCI_CONTROLLER *controller = (XHCI_CONTROLLER *)upipe->CTRL;
    if (eptype != USB_ENDPOINT_XFER_CONTROL || upipe->MPS == oldmp)
    {
        return upipe;
    }

    // Max Packet has changed on control endpoint - update controller
    XHCI_INPUT_CONTROL_CONTEXT *in = (XHCI_INPUT_CONTROL_CONTEXT *)XHCICreateInputContext(common, 1);

    in->ADD = 2;
    XHCI_ENDPOINT_CONTEXT *ep = (XHCI_ENDPOINT_CONTEXT *)(in + (2ULL << controller->CSZ));
    ep->MPSZ = pipe->USB.MPS;

    /********************* Necssary? *********************/
    XHCI_SLOT_CONTEXT *slot = (XHCI_SLOT_CONTEXT *)(in + (1ULL << controller->CSZ));
    uint32_t port = (slot->RHPN - 1);
    uint32_t portsc = controller->PR[port].PSC;
    if (!(portsc & XHCI_PORTSC_CCS))
    {
        return 0;
    }
    /********************* ********* *********************/

    XHCI_TRB_EVALUATE_CONTEXT trb;
    memset(&trb, 0, sizeof(XHCI_TRB_EVALUATE_CONTEXT));
    trb.ICP = virt_to_phys((uint64_t)in);
    trb.TYPE = TRB_EVALUATE_CONTEXT;
    trb.SID = pipe->SID;
    uint32_t cc = XHCICommand(controller, &trb.TRB);
    if (cc != 1)
    {
        printk("CREATE PIPE:EVALUATE CONTROL ENDPOINT FAILED %#04x", cc);
    }
    free_frames(virt_to_phys((uint64_t)in), 1);
    return upipe;
}
uint32_t XHCITransfer(USB_PIPE *pipe, USB_DEVICE_REQUEST *req, void *data, uint32_t xferlen, uint32_t wait)
{
    XHCI_PIPE *xpipe = (XHCI_PIPE *)pipe;
    XHCI_CONTROLLER *controller = (XHCI_CONTROLLER *)pipe->CTRL;
    uint32_t slotid = xpipe->SID;
    XHCI_TRANSFER_RING *ring = &xpipe->RING;
    if (req)
    {
        uint32_t dir = (req->T & 0x80) >> 7;
        if (req->C == USB_REQ_SET_ADDRESS)
            return 0;
        XHCI_TRB_SETUP_STAGE trb0;
        memset(&trb0, 0, sizeof(XHCI_TRB_SETUP_STAGE));
        memcpy(&trb0.DATA, req, sizeof(USB_DEVICE_REQUEST));
        trb0.TL = 8;
        trb0.IDT = 1;
        trb0.TYPE = TRB_SETUP_STAGE;
        trb0.TRT = req->L ? (2 | dir) : 0;
        XHCIQueueTRB(ring, &trb0.TRB);
        if (req->L)
        {
            XHCI_TRB_DATA_STAGE trb1;
            memset(&trb1, 0, sizeof(XHCI_TRB_DATA_STAGE));
            trb1.DATA = translate_address(get_current_page_dir(false), (uint64_t)data);
            trb1.TL = req->L;
            trb1.TYPE = TRB_DATA_STAGE;
            trb1.DIR = dir;
            XHCIQueueTRB(ring, &trb1.TRB);
        }
        XHCI_TRB_STATUS_STAGE trb2;
        memset(&trb2, 0, sizeof(XHCI_TRB_STATUS_STAGE));
        trb2.TYPE = TRB_STATUS_STAGE;
        trb2.IOC = 1;
        trb2.DIR = 1 ^ dir;
        XHCIQueueTRB(ring, &trb2.TRB);
        controller->DR[slotid] = xpipe->EPID;
    }
    else
    {
        // XHCI Transfer Normal
        // while (1) arch_pause();
        XHCI_TRB_NORMAL trb;
        memset(&trb, 0, sizeof(XHCI_TRB_NORMAL));
        trb.DATA = virt_to_phys((uint64_t)data);
        trb.TL = xferlen;
        trb.IOC = 1;
        trb.TYPE = TRB_NORMAL;
        XHCIQueueTRB(ring, &trb.TRB);
        controller->DR[slotid] = xpipe->EPID;
    }
    uint32_t cc = 1;
    if (!wait)
    {
        cc = XHCIWaitCompletion(controller, ring);
    }
    if (cc != 1)
    {
        return cc;
    }
    return 0;
}

void XHCICreateTransferRing(XHCI_TRANSFER_RING *tr)
{
    uint64_t pageAddress = phys_to_virt(alloc_frames(1));
    memset((void *)pageAddress, 0, DEFAULT_PAGE_SIZE);
    tr->RING = (XHCI_TRANSFER_BLOCK *)pageAddress;
    XHCI_TRB_TRANSFER_RING *ring = (XHCI_TRB_TRANSFER_RING *)(tr->RING + XHCI_RING_ITEMS);
    ring->RING = virt_to_phys((uint64_t)tr);
}
