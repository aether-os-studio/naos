// https://gitee.com/BookOS/nxos/blob/master/src/arch/aarch64/kernel/traps.c

#include "irq.h"
#include <arch/arch.h>
#include <task/task.h>
#include <task/signal.h>
#include <mm/fault.h>

#define SEGV_MAPERR 1
#define SEGV_ACCERR 2

extern const uint64_t kallsyms_address[] __attribute__((weak));
extern const uint64_t kallsyms_num __attribute__((weak));
extern const uint64_t kallsyms_names_index[] __attribute__((weak));
extern const char *kallsyms_names __attribute__((weak));

static bool kallsyms_available() {
    return (uintptr_t)kallsyms_address != 0 && (uintptr_t)&kallsyms_num != 0 &&
           (uintptr_t)kallsyms_names_index != 0 &&
           (uintptr_t)&kallsyms_names != 0;
}

static inline bool aarch64_user_mode_frame(const struct pt_regs *frame) {
    return frame && ((frame->cpsr & 0xF) == 0);
}

static uint64_t aarch64_fault_flags(uint32_t ec, uint32_t iss) {
    uint64_t flags = 0;

    if (ec == ESR_ELx_EC_DABT_LOW || ec == ESR_ELx_EC_IABT_LOW)
        flags |= PF_ACCESS_USER;

    if (ec == ESR_ELx_EC_IABT_LOW || ec == ESR_ELx_EC_IABT_CUR) {
        flags |= PF_ACCESS_EXEC;
    } else if (iss & (1U << 6)) {
        flags |= PF_ACCESS_WRITE;
    } else {
        flags |= PF_ACCESS_READ;
    }

    return flags;
}

static bool aarch64_fault_access_allowed_now(task_t *task, uint64_t vaddr,
                                             uint64_t fault_flags) {
    if (!task || !task->mm)
        return false;

    spin_lock(&task->mm->lock);
    uint64_t *table = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint64_t entry = 0;

    for (uint64_t level = 0; level < ARCH_MAX_PT_LEVEL; level++) {
        uint64_t index = PAGE_CALC_PAGE_TABLE_INDEX(vaddr, level + 1);
        entry = table[index];

        if (!(entry & ARCH_PT_FLAG_VALID)) {
            spin_unlock(&task->mm->lock);
            return false;
        }

        if (level == ARCH_MAX_PT_LEVEL - 1 || ARCH_PT_IS_LARGE(entry))
            break;

        if (!ARCH_PT_IS_TABLE(entry)) {
            spin_unlock(&task->mm->lock);
            return false;
        }

        table = (uint64_t *)phys_to_virt(ARCH_READ_PTE(entry));
    }

    uint64_t flags = ARCH_READ_PTE_FLAG(entry);

    if ((fault_flags & PF_ACCESS_USER) && !(flags & ARCH_PT_FLAG_USER)) {
        spin_unlock(&task->mm->lock);
        return false;
    }
    if ((fault_flags & PF_ACCESS_WRITE) && (flags & ARCH_PT_FLAG_READONLY)) {
        spin_unlock(&task->mm->lock);
        return false;
    }
    if ((fault_flags & PF_ACCESS_EXEC) && (flags & ARCH_PT_FLAG_XN)) {
        spin_unlock(&task->mm->lock);
        return false;
    }

    spin_unlock(&task->mm->lock);

    return true;
}

static int aarch64_fault_si_code(uint32_t iss) {
    switch (iss & 0x3F) {
    case 0b000100:
    case 0b000101:
    case 0b000110:
    case 0b000111:
        return SEGV_MAPERR;
    default:
        return SEGV_ACCERR;
    }
}

int lookup_kallsyms(uint64_t addr, int level) {
    printk("function:<unknown>() \t(+) 0000 address:%#018lx\n", addr);
    return 0;
}

void traceback(struct pt_regs *regs) {
    uint64_t fp = regs->x29; // Frame Pointer (x29)
    uint64_t pc = regs->pc;  // Program Counter

    printk("======== Kernel traceback =======\n");

    for (int i = 0; i < 32; ++i) {
        // 检查 FP 有效性
        if (fp == 0)
            break;

        // AArch64 要求栈帧 16 字节对齐
        if (fp & 0xF) {
            printk("  [!] Invalid FP alignment: %#018lx\n", fp);
            break;
        }

        // 查找并打印当前地址的符号
        if (lookup_kallsyms(pc, i) != 0)
            break;

        // 从栈帧读取数据
        uint64_t *frame = (uint64_t *)fp;
        uint64_t next_fp = frame[0]; // [FP + 0]: 前一个 FP
        uint64_t next_pc = frame[1]; // [FP + 8]: 返回地址 (saved LR)

        // 验证下一个 FP（应该在更高地址，因为是调用者的栈帧）
        if (next_fp != 0 && next_fp <= fp) {
            printk("  [!] Invalid FP chain: next=%#018lx, current=%#018lx\n",
                   next_fp, fp);
            break;
        }

        // 更新到下一个栈帧
        fp = next_fp;
        pc = next_pc;
    }

    printk("======== Kernel traceback end =======\n");

    pc = regs->pc; // Program Counter

    if (regs->pc >= get_physical_memory_offset())
        return;

    printk("======== User traceback =======\n");

    task_t *self = current_task;

    if (self) {
        rb_node_t *node = rb_first(&self->mm->task_vma_mgr.vma_tree);

        while (node) {
            vma_t *vma = rb_entry(node, vma_t, vm_rb);
            if (vma->vm_name) {
                if (pc >= vma->vm_start && pc <= vma->vm_end) {
                    printk("Fault in this vma: %s, vma->vm_start = %#018lx, "
                           "offset_in_vma = %#018lx, vma->flags = %#010x\n",
                           vma->vm_name, vma->vm_start, pc - vma->vm_start,
                           vma->vm_flags);
                } else {
                    printk("Faulting task vma: %s, vma->vm_start = %#018lx, "
                           "vma->flags = %#010x\n",
                           vma->vm_name, vma->vm_start, vma->vm_flags);
                }
            }

            node = rb_next(node);
        }

        struct pt_regs *syscall_regs =
            (struct pt_regs *)self->syscall_stack - 1;

        printk("Last syscall registers:\n");
        printk("X00:%#018lx X01:%#018lx X02:%#018lx X03:%#018lx\r\n", regs->x0,
               syscall_regs->x1, syscall_regs->x2, syscall_regs->x3);
        printk("X04:%#018lx X05:%#018lx X06:%#018lx X07:%#018lx\r\n",
               syscall_regs->x4, syscall_regs->x5, syscall_regs->x6,
               syscall_regs->x7);
        printk("X08:%#018lx X09:%#018lx X10:%#018lx X11:%#018lx\r\n",
               syscall_regs->x8, syscall_regs->x9, syscall_regs->x10,
               syscall_regs->x11);
        printk("X12:%#018lx X13:%#018lx X14:%#018lx X15:%#018lx\r\n",
               syscall_regs->x12, syscall_regs->x13, syscall_regs->x14,
               syscall_regs->x15);
        printk("X16:%#018lx X17:%#018lx X18:%#018lx X19:%#018lx\r\n",
               syscall_regs->x16, syscall_regs->x17, syscall_regs->x18,
               syscall_regs->x19);
        printk("X20:%#018lx X21:%#018lx X22:%#018lx X23:%#018lx\r\n",
               syscall_regs->x20, syscall_regs->x21, syscall_regs->x22,
               syscall_regs->x23);
        printk("X24:%#018lx X25:%#018lx X26:%#018lx X27:%#018lx\r\n",
               syscall_regs->x24, syscall_regs->x25, syscall_regs->x26,
               syscall_regs->x27);
        printk("X28:%#018lx X29:%#018lx X30:%#018lx\r\n", syscall_regs->x28,
               syscall_regs->x29, syscall_regs->x30);
        printk("SP_EL0:%#018lx\r\n", syscall_regs->sp_el0);
        printk("SPSR  :%#018lx\r\n", syscall_regs->cpsr);
        printk("EPC   :%#018lx\r\n", syscall_regs->pc);
    }

    printk("======== User traceback end =======\n");
}

void show_frame(struct pt_regs *regs) {
    if (current_task)
        printk("current_task->name = %s, current_task->pid = %d\n",
               current_task->name, current_task->pid);

    traceback(regs);

    printk("Exception:\r\n");
    printk("X00:%#018lx X01:%#018lx X02:%#018lx X03:%#018lx\r\n", regs->x0,
           regs->x1, regs->x2, regs->x3);
    printk("X04:%#018lx X05:%#018lx X06:%#018lx X07:%#018lx\r\n", regs->x4,
           regs->x5, regs->x6, regs->x7);
    printk("X08:%#018lx X09:%#018lx X10:%#018lx X11:%#018lx\r\n", regs->x8,
           regs->x9, regs->x10, regs->x11);
    printk("X12:%#018lx X13:%#018lx X14:%#018lx X15:%#018lx\r\n", regs->x12,
           regs->x13, regs->x14, regs->x15);
    printk("X16:%#018lx X17:%#018lx X18:%#018lx X19:%#018lx\r\n", regs->x16,
           regs->x17, regs->x18, regs->x19);
    printk("X20:%#018lx X21:%#018lx X22:%#018lx X23:%#018lx\r\n", regs->x20,
           regs->x21, regs->x22, regs->x23);
    printk("X24:%#018lx X25:%#018lx X26:%#018lx X27:%#018lx\r\n", regs->x24,
           regs->x25, regs->x26, regs->x27);
    printk("X28:%#018lx X29:%#018lx X30:%#018lx\r\n", regs->x28, regs->x29,
           regs->x30);
    printk("SP_EL0:%#018lx\r\n", regs->sp_el0);
    printk("SPSR  :%#018lx\r\n", regs->cpsr);
    printk("EPC   :%#018lx\r\n", regs->pc);
}

static void data_abort(unsigned long far, unsigned long iss) {
    printk("fault addr = 0x%016lx\r\n", far);
    if (iss & 0x40) {
        printk("abort caused by write instruction\r\n");
    } else {
        printk("abort caused by read instruction\r\n");
    }
    switch (iss & 0x3f) {
    case 0b000000:
        printk("Address size fault, zeroth level of translation or translation "
               "table base register\r\n");
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
        printk("Synchronous parity or ECC error on memory access, not on "
               "translation table walk\r\n");
        break;

    case 0b010100:
        printk("Synchronous external abort on translation table walk, zeroth "
               "level\r\n");
        break;

    case 0b010101:
        printk("Synchronous external abort on translation table walk, first "
               "level\r\n");
        break;

    case 0b010110:
        printk("Synchronous external abort on translation table walk, second "
               "level\r\n");
        break;

    case 0b010111:
        printk("Synchronous external abort on translation table walk, third "
               "level\r\n");
        break;

    case 0b011100:
        printk("Synchronous parity or ECC error on memory access on "
               "translation table walk, zeroth level\r\n");
        break;

    case 0b011101:
        printk("Synchronous parity or ECC error on memory access on "
               "translation table walk, first level\r\n");
        break;

    case 0b011110:
        printk("Synchronous parity or ECC error on memory access on "
               "translation table walk, second level\r\n");
        break;

    case 0b011111:
        printk("Synchronous parity or ECC error on memory access on "
               "translation table walk, third level\r\n");
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
        printk("IMPLEMENTATION DEFINED fault (Unsupported Exclusive access "
               "fault)\r\n");
        break;

    case 0b111101:
        printk("Section Domain Fault, used only for faults reported in the "
               "PAR_EL1\r\n");
        break;

    case 0b111110:
        printk("Page Domain Fault, used only for faults reported in the "
               "PAR_EL1\r\n");
        break;

    default:
        printk("unknow abort\r\n");
        break;
    }

    task_exit(SIGSEGV + 128);
}

void process_exception(struct pt_regs *frame, unsigned long esr,
                       unsigned long epc) {
    uint8_t ec;
    uint32_t iss;
    unsigned long fault_addr;
    printk("\nexception info:\r\n");
    ec = (unsigned char)((esr >> 26) & 0x3fU);
    iss = (unsigned int)(esr & 0x00ffffffU);
    printk("esr.EC :0x%02x\r\n", ec);
    printk("esr.IL :0x%02x\r\n", (unsigned char)((esr >> 25) & 0x01U));
    printk("esr.ISS:0x%08x\r\n", iss);
    printk("epc    :%#018lx\r\n", epc);
    switch (ec) {
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
        printk(
            "Exceptions from an MCRR or MRRC access to CP15 from AArch32\r\n");
        break;

    case 0x05:
        printk("Exceptions from an MCR or MRC access to CP14 from AArch32\r\n");
        break;

    case 0x06:
        printk("Exceptions from an LDC or STC access to CP14 from AArch32\r\n");
        break;

    case 0x07:
        printk("Exceptions from Access to Advanced SIMD or floating-point "
               "registers\r\n");
        break;

    case 0x08:
        printk(
            "Exceptions from an MRC (or VMRS) access to CP10 from AArch32\r\n");
        break;

    case 0x0c:
        printk(
            "Exceptions from an MCRR or MRRC access to CP14 from AArch32\r\n");
        break;

    case 0x0e:
        printk(
            "Exceptions that occur because ther value of PSTATE.IL is 1\r\n");
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
        asm volatile("mrs %0, far_el1" : "=r"(fault_addr));
        data_abort(fault_addr, iss);
        break;

    case ESR_ELx_EC_DABT_CUR:
        printk("Data abort\r\n");
        asm volatile("mrs %0, far_el1" : "=r"(fault_addr));
        data_abort(fault_addr, iss);
        break;

    default:
        printk("Other error\r\n");
        break;
    }
}

void handle_exception(struct pt_regs *frame) {
    unsigned long esr;
    unsigned char ec;
    uint32_t iss;
    unsigned long fault_addr;

    asm volatile("mrs %0, esr_el1" : "=r"(esr));
    ec = (unsigned char)((esr >> 26) & 0x3fU);
    iss = (uint32_t)(esr & 0x00ffffffU);

    if (ec == ESR_ELx_EC_SVC64) /* is 64bit syscall ? */
    {
        struct pt_regs *syscall_frame =
            (struct pt_regs *)current_task->syscall_stack - 1;
        memcpy(syscall_frame, frame, sizeof(struct pt_regs));
        aarch64_do_syscall(syscall_frame);
        memcpy(frame, syscall_frame, sizeof(struct pt_regs));
        return;
    }

    if (ec == ESR_ELx_EC_DABT_LOW || ec == ESR_ELx_EC_DABT_CUR ||
        ec == ESR_ELx_EC_IABT_LOW || ec == ESR_ELx_EC_IABT_CUR) {
        if (ec == ESR_ELx_EC_IABT_LOW || ec == ESR_ELx_EC_IABT_CUR)
            fault_addr = frame->pc;
        else
            asm volatile("mrs %0, far_el1" : "=r"(fault_addr));

        uint64_t fault_flags = aarch64_fault_flags(ec, iss);
        page_fault_result_t result =
            handle_page_fault_flags(current_task, fault_addr, fault_flags);
        if (result == PF_RES_OK) {
            return;
        } else if (aarch64_fault_access_allowed_now(current_task, fault_addr,
                                                    fault_flags)) {
            arch_flush_tlb(fault_addr);
            return;
        } else if (result == PF_RES_SEGF) {
            // if (aarch64_user_mode_frame(frame) && current_task) {
            //     siginfo_t info;
            //     memset(&info, 0, sizeof(info));
            //     info.si_signo = SIGSEGV;
            //     info.si_code = aarch64_fault_si_code((uint32_t)esr);
            //     info._sifields._sigfault._addr = (void *)fault_addr;
            //     task_commit_signal(current_task, SIGSEGV, &info);
            //     task_signal(frame);
            //     return;
            // }

            printk("fault_addr = %p, fault_flags = %#018x\n", fault_addr,
                   fault_flags);
            show_frame(frame);
            task_exit(SIGSEGV + 128);
        } else if (result == PF_RES_NOMEM) {
            printk("Out of memory in kernel space\r\n");
            task_exit(SIGKILL + 128);
        } else {
            printk("Unknown page fault result\r\n");
            printk("fault_addr = %p\n", fault_addr);
            show_frame(frame);
            task_exit(SIGKILL + 128);
        }
    }

    process_exception(frame, esr, frame->pc);
    show_frame(frame);

    while (1) {
        arch_pause();
    }
}

void bad_mode(struct pt_regs *frame, int reason, unsigned int esr) {
    printk("bad mode:\n");
    printk("reason = %d\n", reason);

    uint8_t ec = (uint8_t)((esr >> 26) & 0x3fU);
    uint32_t iss = (uint32_t)(esr & 0x00ffffffU);
    printk("esr.EC :0x%02x\r\n", ec);
    printk("esr.IL :0x%02x\r\n", (uint8_t)((esr >> 25) & 0x01U));
    printk("esr.ISS:0x%08x\r\n", iss);

    show_frame(frame);

    arch_disable_interrupt();

    while (1) {
        arch_pause();
    }
}

void trap_dispatch(struct pt_regs *frame) { handle_exception(frame); }
