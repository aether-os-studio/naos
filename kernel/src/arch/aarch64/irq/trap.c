// https://gitee.com/BookOS/nxos/blob/master/src/arch/aarch64/kernel/traps.c

#include "irq.h"
#include <arch/arch.h>

void show_frame(struct pt_regs *regs)
{
    printk("Execption:\r\n");
    printk("X00:%#018lx X01:%#018lx X02:%#018lx X03:%#018lx\r\n", regs->x0, regs->x1, regs->x2, regs->x3);
    printk("X04:%#018lx X05:%#018lx X06:%#018lx X07:%#018lx\r\n", regs->x4, regs->x5, regs->x6, regs->x7);
    printk("X08:%#018lx X09:%#018lx X10:%#018lx X11:%#018lx\r\n", regs->x8, regs->x9, regs->x10, regs->x11);
    printk("X12:%#018lx X13:%#018lx X14:%#018lx X15:%#018lx\r\n", regs->x12, regs->x13, regs->x14, regs->x15);
    printk("X16:%#018lx X17:%#018lx X18:%#018lx X19:%#018lx\r\n", regs->x16, regs->x17, regs->x18, regs->x19);
    printk("X20:%#018lx X21:%#018lx X22:%#018lx X23:%#018lx\r\n", regs->x20, regs->x21, regs->x22, regs->x23);
    printk("X24:%#018lx X25:%#018lx X26:%#018lx X27:%#018lx\r\n", regs->x24, regs->x25, regs->x26, regs->x27);
    printk("X28:%#018lx X29:%#018lx X30:%#018lx\r\n", regs->x28, regs->x29, regs->x30);
    printk("SP_EL0:%#018lx\r\n", regs->sp_el0);
    printk("SPSR  :%#018lx\r\n", regs->cpsr);
    printk("EPC   :%#018lx\r\n", regs->pc);
}

static void data_abort(unsigned long far, unsigned long iss)
{
    printk("fault addr = 0x%016lx\r\n", far);
    if (iss & 0x40)
    {
        printk("abort caused by write instruction\r\n");
    }
    else
    {
        printk("abort caused by read instruction\r\n");
    }
    switch (iss & 0x3f)
    {
    case 0b000000:
        printk("Address size fault, zeroth level of translation or translation table base register\r\n");
        break;

    case 0b000001:
        printk("Address size fault, first level\r\n");
        break;

    case 0b000010:
        printk("Address size fault, second level\r\n");
        break;

    case 0b000011:
        printk("Address size fault, third level\r\n");
        break;

    case 0b000100:
        printk("Translation fault, zeroth level\r\n");
        break;

    case 0b000101:
        printk("Translation fault, first level\r\n");
        break;

    case 0b000110:
        printk("Translation fault, second level\r\n");
        break;

    case 0b000111:
        printk("Translation fault, third level\r\n");
        break;

    case 0b001001:
        printk("Access flag fault, first level\r\n");
        break;

    case 0b001010:
        printk("Access flag fault, second level\r\n");
        break;

    case 0b001011:
        printk("Access flag fault, third level\r\n");
        break;

    case 0b001101:
        printk("Permission fault, first level\r\n");
        break;

    case 0b001110:
        printk("Permission fault, second level\r\n");
        break;

    case 0b001111:
        printk("Permission fault, third level\r\n");
        break;

    case 0b010000:
        printk("Synchronous external abort, not on translation table walk\r\n");
        break;

    case 0b011000:
        printk("Synchronous parity or ECC error on memory access, not on translation table walk\r\n");
        break;

    case 0b010100:
        printk("Synchronous external abort on translation table walk, zeroth level\r\n");
        break;

    case 0b010101:
        printk("Synchronous external abort on translation table walk, first level\r\n");
        break;

    case 0b010110:
        printk("Synchronous external abort on translation table walk, second level\r\n");
        break;

    case 0b010111:
        printk("Synchronous external abort on translation table walk, third level\r\n");
        break;

    case 0b011100:
        printk("Synchronous parity or ECC error on memory access on translation table walk, zeroth level\r\n");
        break;

    case 0b011101:
        printk("Synchronous parity or ECC error on memory access on translation table walk, first level\r\n");
        break;

    case 0b011110:
        printk("Synchronous parity or ECC error on memory access on translation table walk, second level\r\n");
        break;

    case 0b011111:
        printk("Synchronous parity or ECC error on memory access on translation table walk, third level\r\n");
        break;

    case 0b100001:
        printk("Alignment fault\r\n");
        break;

    case 0b110000:
        printk("TLB conflict abort\r\n");
        break;

    case 0b110100:
        printk("IMPLEMENTATION DEFINED fault (Lockdown fault)\r\n");
        break;

    case 0b110101:
        printk("IMPLEMENTATION DEFINED fault (Unsupported Exclusive access fault)\r\n");
        break;

    case 0b111101:
        printk("Section Domain Fault, used only for faults reported in the PAR_EL1\r\n");
        break;

    case 0b111110:
        printk("Page Domain Fault, used only for faults reported in the PAR_EL1\r\n");
        break;

    default:
        printk("unknow abort\r\n");
        break;
    }
}

void process_exception(struct pt_regs *frame, unsigned long esr, unsigned long epc)
{
    uint8_t ec;
    uint32_t iss;
    unsigned long fault_addr;
    printk("\nexception info:\r\n");
    ec = (unsigned char)((esr >> 26) & 0x3fU);
    iss = (unsigned int)(esr & 0x00ffffffU);
    printk("esr.EC :0x%02x\r\n", ec);
    printk("esr.IL :0x%02x\r\n", (unsigned char)((esr >> 25) & 0x01U));
    printk("esr.ISS:0x%08x\r\n", iss);
    printk("epc    :0x%016p\r\n", epc);
    switch (ec)
    {
    case 0x00:
        printk("Exceptions with an unknow reason\r\n");
        break;

    case 0x01:
        printk("Exceptions from an WFI or WFE instruction\r\n");
        break;

    case 0x03:
        printk("Exceptions from an MCR or MRC access to CP15 from AArch32\r\n");
        break;

    case 0x04:
        printk("Exceptions from an MCRR or MRRC access to CP15 from AArch32\r\n");
        break;

    case 0x05:
        printk("Exceptions from an MCR or MRC access to CP14 from AArch32\r\n");
        break;

    case 0x06:
        printk("Exceptions from an LDC or STC access to CP14 from AArch32\r\n");
        break;

    case 0x07:
        printk("Exceptions from Access to Advanced SIMD or floating-point registers\r\n");
        break;

    case 0x08:
        printk("Exceptions from an MRC (or VMRS) access to CP10 from AArch32\r\n");
        break;

    case 0x0c:
        printk("Exceptions from an MCRR or MRRC access to CP14 from AArch32\r\n");
        break;

    case 0x0e:
        printk("Exceptions that occur because ther value of PSTATE.IL is 1\r\n");
        break;

    case 0x11:
        printk("SVC call from AArch32 state\r\n");
        break;

    case 0x15:
        printk("SVC call from AArch64 state\r\n");
        break;

    case 0x20:
        printk("Instruction abort from lower exception level\r\n");
        break;

    case 0x21:
        printk("Instruction abort from current exception level\r\n");
        break;

    case 0x22:
        printk("PC alignment fault\r\n");
        break;

    case ESR_ELx_EC_DABT_LOW:
        printk("Data abort from a lower Exception level\r\n");
        __asm__ volatile("mrs %0, far_el1" : "=r"(fault_addr));
        data_abort(fault_addr, iss);
        break;

    case ESR_ELx_EC_DABT_CUR:
        printk("Data abort\r\n");
        __asm__ volatile("mrs %0, far_el1" : "=r"(fault_addr));
        data_abort(fault_addr, iss);
        break;

    default:
        printk("Other error\r\n");
        break;
    }
}

void handle_exception(struct pt_regs *frame)
{
    unsigned long esr;
    unsigned char ec;
    unsigned long fault_addr;

    asm volatile("mrs %0, esr_el1" : "=r"(esr));
    ec = (unsigned char)((esr >> 26) & 0x3fU);

    // if (ec == ESR_ELx_EC_SVC64) /* is 64bit syscall ? */
    // {
    //     /* never return here */
    //     process_syscall(frame);
    //     return;
    // }

    if (ec == ESR_ELx_EC_DABT_LOW || ec == ESR_ELx_EC_DABT_CUR)
    {
        __asm__ volatile("mrs %0, far_el1" : "=r"(fault_addr));
        // if (NX_HalHandlePageFault(NX_ThreadSelf(), frame, fault_addr) == NX_EOK)
        // {
        //     return;
        // }
        printk("fault address = %#018lx", fault_addr);
    }

    process_exception(frame, esr, frame->pc);
    show_frame(frame);

    while (1)
    {
        arch_pause();
    }
}

void bad_mode(struct pt_regs *frame, int reason, unsigned int esr)
{
    show_frame(frame);

    while (1)
    {
        arch_pause();
    }
}

void trap_dispatch(struct pt_regs *frame)
{
    handle_exception(frame);
    // IRQ_OverCheck(frame);
    // IRQ_OverCheck2(frame);
}
