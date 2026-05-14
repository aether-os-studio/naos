#include "irq.h"
#include <arch/arch.h>
#include <arch/riscv64/smp/smp.h>
#include <mod/dlinker.h>
#include <irq/irq_manager.h>
#include <mm/fault.h>
#include <task/signal.h>
#include <task/task.h>

extern void do_irq(struct pt_regs *regs, uint64_t irq_num);

#define RISCV_SCAUSE_INTERRUPT (1ULL << 63)
#define RISCV_SCAUSE_CODE_MASK ((1ULL << 63) - 1)

#define RISCV_SCAUSE_SUPERVISOR_SOFTWARE 1
#define RISCV_SCAUSE_SUPERVISOR_TIMER 5
#define RISCV_SCAUSE_SUPERVISOR_EXTERNAL 9

#define RISCV_SCAUSE_ENV_CALL_FROM_U 8
#define RISCV_SCAUSE_ILLEGAL_INSTRUCTION 2

#define RISCV_SCAUSE_INST_PAGE_FAULT 12
#define RISCV_SCAUSE_LOAD_PAGE_FAULT 13
#define RISCV_SCAUSE_STORE_PAGE_FAULT 15

#define RISCV_TRACEBACK_MAX_DEPTH 32
#define RISCV_SSTATUS_SPP (1UL << 8)
#define RISCV_SSTATUS_SUM (1UL << 18)

void arch_enable_interrupt() {
    asm volatile("csrsi sstatus, 0x2" ::: "memory");
}

void arch_disable_interrupt() {
    asm volatile("csrci sstatus, 0x2" ::: "memory");
}

bool arch_interrupt_enabled() {
    uint64_t sstatus;
    asm volatile("csrr %0, sstatus" : "=r"(sstatus));
    return (sstatus & 0x2) != 0;
}

static bool riscv_user_mode_frame(const struct pt_regs *regs) {
    return regs && ((regs->sstatus & RISCV_SSTATUS_SPP) == 0);
}

static bool riscv_sum_user_data_fault(const struct pt_regs *regs,
                                      uint64_t cause) {
    if (!regs || !current_task || !current_task->mm)
        return false;
    if (riscv_user_mode_frame(regs))
        return false;
    if (cause != RISCV_SCAUSE_LOAD_PAGE_FAULT &&
        cause != RISCV_SCAUSE_STORE_PAGE_FAULT) {
        return false;
    }
    if ((regs->sstatus & RISCV_SSTATUS_SUM) == 0)
        return false;

    return regs->stval != 0 && regs->stval < get_physical_memory_offset();
}

static uint64_t riscv_fault_flags(const struct pt_regs *regs) {
    uint64_t cause = regs->scause & RISCV_SCAUSE_CODE_MASK;
    uint64_t flags = 0;

    if (riscv_user_mode_frame(regs) || riscv_sum_user_data_fault(regs, cause))
        flags |= PF_ACCESS_USER;

    switch (cause) {
    case RISCV_SCAUSE_INST_PAGE_FAULT:
        return flags | PF_ACCESS_EXEC;
    case RISCV_SCAUSE_STORE_PAGE_FAULT:
        return flags | PF_ACCESS_WRITE;
    case RISCV_SCAUSE_LOAD_PAGE_FAULT:
    default:
        return flags | PF_ACCESS_READ;
    }
}

static int riscv_lookup_kallsyms(uint64_t addr, int level) {
    symbol_lookup_result_t symbol = {0};

    if (!dlinker_lookup_symbol_by_addr(addr, &symbol) || symbol.name == NULL) {
        printk("#%02d <unknown> address:%#018lx\n", level, addr);
        return 0;
    }

    if (symbol.is_module) {
        if (symbol.symbol_size != 0) {
            printk("#%02d %s+%#lx/%#lx [%s] address:%#018lx%s\n", level,
                   symbol.name, symbol.offset, symbol.symbol_size,
                   symbol.module_name ? symbol.module_name : "<module>", addr,
                   symbol.exact_match ? "" : " (nearest)");
        } else {
            printk("#%02d %s+%#lx [%s] address:%#018lx%s\n", level, symbol.name,
                   symbol.offset,
                   symbol.module_name ? symbol.module_name : "<module>", addr,
                   symbol.exact_match ? "" : " (nearest)");
        }
    } else if (symbol.symbol_size != 0) {
        printk("#%02d %s+%#lx/%#lx [kernel] address:%#018lx%s\n", level,
               symbol.name, symbol.offset, symbol.symbol_size, addr,
               symbol.exact_match ? "" : " (nearest)");
    } else {
        printk("#%02d %s+%#lx [kernel] address:%#018lx%s\n", level, symbol.name,
               symbol.offset, addr, symbol.exact_match ? "" : " (nearest)");
    }

    return 0;
}

static void riscv_traceback(struct pt_regs *regs) {
    uint64_t fp = regs->s0;
    uint64_t pc = regs->sepc;

    if (pc >= get_physical_memory_offset()) {
        printk("======== Kernel traceback =======\n");

        for (int i = 0; i < RISCV_TRACEBACK_MAX_DEPTH; ++i) {
            if (pc < get_physical_memory_offset())
                break;

            if (riscv_lookup_kallsyms(pc, i) != 0)
                break;

            if (!fp || (fp & 0xFUL)) {
                if (fp & 0xFUL)
                    printk("  [!] Invalid FP alignment: %#018lx\n", fp);
                break;
            }

            uint64_t *frame = (uint64_t *)fp;
            uint64_t next_fp = frame[-2];
            uint64_t next_pc = frame[-1];

            if (next_fp != 0 && next_fp <= fp) {
                printk(
                    "  [!] Invalid FP chain: next=%#018lx, current=%#018lx\n",
                    next_fp, fp);
                break;
            }

            fp = next_fp;
            pc = next_pc;
        }

        printk("======== Kernel traceback end =======\n");
        return;
    }

    printk("======== User traceback =======\n");

    task_t *self = current_task;
    if (self && self->mm) {
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
        printk("SEPC = %#018lx\n", syscall_regs->sepc);
        printk("RA   = %#018lx SP   = %#018lx\n", syscall_regs->ra,
               syscall_regs->sp);
        printk("A0   = %#018lx A1   = %#018lx\n", syscall_regs->a0,
               syscall_regs->a1);
        printk("A2   = %#018lx A3   = %#018lx\n", syscall_regs->a2,
               syscall_regs->a3);
        printk("A4   = %#018lx A5   = %#018lx\n", syscall_regs->a4,
               syscall_regs->a5);
        printk("A6   = %#018lx A7   = %#018lx\n", syscall_regs->a6,
               syscall_regs->a7);
        printk("S0   = %#018lx S1   = %#018lx\n", syscall_regs->s0,
               syscall_regs->s1);
        printk("S2   = %#018lx S3   = %#018lx\n", syscall_regs->s2,
               syscall_regs->s3);
        printk("S4   = %#018lx S5   = %#018lx\n", syscall_regs->s4,
               syscall_regs->s5);
        printk("S6   = %#018lx S7   = %#018lx\n", syscall_regs->s6,
               syscall_regs->s7);
        printk("S8   = %#018lx S9   = %#018lx\n", syscall_regs->s8,
               syscall_regs->s9);
        printk("S10  = %#018lx S11  = %#018lx\n", syscall_regs->s10,
               syscall_regs->s11);
    }

    printk("======== User traceback end =======\n");
}

static void riscv_show_frame(struct pt_regs *regs) {
    if (current_task) {
        printk("current_task->name = %s, current_task->pid = %lu\n",
               current_task->name, current_task->pid);
    }

    if (!check_unmapped(regs->sepc, sizeof(uint32_t))) {
        printk("instruction: %#010x\n", *(uint32_t *)regs->sepc);
    }

    riscv_traceback(regs);

    printk("Exception:\n");
    printk("RA   = %#018lx SP   = %#018lx GP   = %#018lx TP   = %#018lx\n",
           regs->ra, regs->sp, regs->gp, regs->tp);
    printk("T0   = %#018lx T1   = %#018lx T2   = %#018lx\n", regs->t0, regs->t1,
           regs->t2);
    printk("S0   = %#018lx S1   = %#018lx\n", regs->s0, regs->s1);
    printk("A0   = %#018lx A1   = %#018lx A2   = %#018lx A3   = %#018lx\n",
           regs->a0, regs->a1, regs->a2, regs->a3);
    printk("A4   = %#018lx A5   = %#018lx A6   = %#018lx A7   = %#018lx\n",
           regs->a4, regs->a5, regs->a6, regs->a7);
    printk("S2   = %#018lx S3   = %#018lx S4   = %#018lx S5   = %#018lx\n",
           regs->s2, regs->s3, regs->s4, regs->s5);
    printk("S6   = %#018lx S7   = %#018lx S8   = %#018lx S9   = %#018lx\n",
           regs->s6, regs->s7, regs->s8, regs->s9);
    printk("S10  = %#018lx S11  = %#018lx\n", regs->s10, regs->s11);
    printk("T3   = %#018lx T4   = %#018lx T5   = %#018lx T6   = %#018lx\n",
           regs->t3, regs->t4, regs->t5, regs->t6);
    printk(
        "SEPC = %#018lx SSTATUS = %#018lx STVAL = %#018lx SCAUSE = %#018lx\n",
        regs->sepc, regs->sstatus, regs->stval, regs->scause);
}

static void riscv_unhandled_trap(struct pt_regs *regs) {
    printk("Unhandled RISC-V trap: scause=%#018lx sepc=%#018lx stval=%#018lx "
           "sstatus=%#018lx\n",
           regs->scause, regs->sepc, regs->stval, regs->sstatus);
    if (current_task) {
        printk("current_task=%s pid=%lu\n", current_task->name,
               current_task->pid);
    }
    panic(__FILE__, __LINE__, __func__, "unhandled riscv64 trap");
}

static void riscv_handle_page_fault(struct pt_regs *regs) {
    if (!current_task) {
        riscv_unhandled_trap(regs);
    }

    page_fault_result_t result = handle_page_fault_flags(
        current_task, regs->stval, riscv_fault_flags(regs));
    if (result == PF_RES_OK)
        return;

    printk(
        "RISC-V page fault unresolved: result=%d stval=%#018lx flags=%#018lx\n",
        result, regs->stval, riscv_fault_flags(regs));
    riscv_show_frame(regs);
    task_exit(128 + SIGSEGV);
}

static void riscv_handle_illegal_instruction(struct pt_regs *regs) {
    if (!riscv_user_mode_frame(regs) || !current_task)
        riscv_unhandled_trap(regs);

    task_exit(128 + SIGILL);
}

void trap_dispatch(struct pt_regs *regs) {
    uint64_t scause = regs->scause;
    uint64_t cause = scause & RISCV_SCAUSE_CODE_MASK;

    if (scause & RISCV_SCAUSE_INTERRUPT) {
        switch (cause) {
        case RISCV_SCAUSE_SUPERVISOR_TIMER:
            do_irq(regs, ARCH_TIMER_IRQ);
            return;
        case RISCV_SCAUSE_SUPERVISOR_SOFTWARE:
            do_irq(regs, riscv64_sched_ipi_irq());
            return;
        case RISCV_SCAUSE_SUPERVISOR_EXTERNAL:
            return;
        default:
            riscv_unhandled_trap(regs);
            return;
        }
    }

    switch (cause) {
    case RISCV_SCAUSE_ILLEGAL_INSTRUCTION:
        riscv_handle_illegal_instruction(regs);
        return;
    case RISCV_SCAUSE_ENV_CALL_FROM_U:
        riscv64_do_syscall(regs);
        return;
    case RISCV_SCAUSE_INST_PAGE_FAULT:
    case RISCV_SCAUSE_LOAD_PAGE_FAULT:
    case RISCV_SCAUSE_STORE_PAGE_FAULT:
        riscv_handle_page_fault(regs);
        return;
    default:
        riscv_unhandled_trap(regs);
        return;
    }
}

void irq_init() {
    setup_trap_vector();
    asm volatile("csrsi sie, 0x2" ::: "memory");
}
