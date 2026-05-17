#include <arch/loongarch64/csr.h>
#include <arch/loongarch64/irq/irq.h>
#include <arch/loongarch64/time/time.h>
#include <arch/loongarch64/syscall/syscall.h>
#include <irq/irq_manager.h>
#include <mm/fault.h>
#include <task/signal.h>
#include <task/task.h>

extern void loongarch64_trap_entry();
extern void do_irq(struct pt_regs *regs, uint64_t irq_num);

void arch_enable_interrupt() { csr_set(LOONGARCH_CSR_CRMD, LOONGARCH_CRMD_IE); }
void arch_disable_interrupt() {
    csr_clear(LOONGARCH_CSR_CRMD, LOONGARCH_CRMD_IE);
}
bool arch_interrupt_enabled() {
    return (csr_read(LOONGARCH_CSR_CRMD) & LOONGARCH_CRMD_IE) != 0;
}

static bool loongarch64_user_mode_frame(const struct pt_regs *regs) {
    return regs &&
           ((regs->csr_prmd & LOONGARCH_PRMD_PPLV_MASK) == LOONGARCH_PLV_USER);
}

static void loongarch64_handle_signal_on_user_return(struct pt_regs *regs) {
    if (loongarch64_user_mode_frame(regs) && current_task &&
        current_task->signal && current_task->signal->signal) {
        task_signal(regs);
    }
}

static void loongarch64_unhandled_trap(struct pt_regs *regs) {
    printk("Unhandled LoongArch trap: estat=%#018lx era=%#018lx badv=%#018lx "
           "prmd=%#018lx\n",
           regs->csr_estat, regs->pc, regs->csr_badv, regs->csr_prmd);
    if (current_task) {
        printk("current_task=%s pid=%lu\n", current_task->name,
               current_task->pid);
    }
    panic(__FILE__, __LINE__, __func__, "unhandled loongarch64 trap");
}

static bool loongarch64_page_fault_ecode(uint64_t ecode) {
    switch (ecode) {
    case LOONGARCH_ECODE_PIL:
    case LOONGARCH_ECODE_PIS:
    case LOONGARCH_ECODE_PIF:
    case LOONGARCH_ECODE_PME:
    case LOONGARCH_ECODE_PNR:
    case LOONGARCH_ECODE_PNX:
    case LOONGARCH_ECODE_PPI:
        return true;
    default:
        return false;
    }
}

static uint64_t loongarch64_fault_flags(const struct pt_regs *regs,
                                        uint64_t ecode) {
    uint64_t flags = 0;

    if (loongarch64_user_mode_frame(regs))
        flags |= PF_ACCESS_USER;

    switch (ecode) {
    case LOONGARCH_ECODE_PIS:
    case LOONGARCH_ECODE_PME:
        return flags | PF_ACCESS_WRITE;
    case LOONGARCH_ECODE_PIF:
    case LOONGARCH_ECODE_PNX:
        return flags | PF_ACCESS_EXEC;
    case LOONGARCH_ECODE_PIL:
    case LOONGARCH_ECODE_PNR:
    case LOONGARCH_ECODE_PPI:
    default:
        return flags | PF_ACCESS_READ;
    }
}

static void loongarch64_handle_page_fault(struct pt_regs *regs,
                                          uint64_t ecode) {
    if (!current_task) {
        loongarch64_unhandled_trap(regs);
    }

    uint64_t fault_addr = regs->csr_badv;
    uint64_t fault_flags = loongarch64_fault_flags(regs, ecode);
    page_fault_result_t result =
        handle_page_fault_flags(current_task, fault_addr, fault_flags);

    if (result == PF_RES_OK)
        return;

    printk("LoongArch page fault unresolved: result=%d ecode=%#lx "
           "badv=%#018lx era=%#018lx flags=%#018lx\n",
           result, ecode, fault_addr, regs->pc, fault_flags);
    task_exit(128 + SIGSEGV);
}

void loongarch64_trap_dispatch(struct pt_regs *regs) {
    uint64_t pending = regs->csr_estat & LOONGARCH_ESTAT_IS_MASK;
    uint64_t ecode = (regs->csr_estat >> LOONGARCH_ESTAT_ECODE_SHIFT) &
                     LOONGARCH_ESTAT_ECODE_MASK;

    if (ecode == LOONGARCH_ECODE_INT) {
        if (pending & LOONGARCH_ECFG_TIMER) {
            do_irq(regs, ARCH_TIMER_IRQ);
            loongarch64_handle_signal_on_user_return(regs);
            return;
        }

        loongarch64_unhandled_trap(regs);
    }

    if (ecode == LOONGARCH_ECODE_SYS) {
        loongarch64_do_syscall(regs);
        return;
    }

    if (loongarch64_page_fault_ecode(ecode)) {
        loongarch64_handle_page_fault(regs, ecode);
        loongarch64_handle_signal_on_user_return(regs);
        return;
    }

    loongarch64_unhandled_trap(regs);
}

void irq_init() {
    uint64_t ecfg = csr_read(LOONGARCH_CSR_ECFG);

    csr_write(LOONGARCH_CSR_EENTRY, (uint64_t)loongarch64_trap_entry);
    ecfg &= ~LOONGARCH_ECFG_VS_MASK;
    ecfg |= LOONGARCH_ECFG_TIMER;
    csr_write(LOONGARCH_CSR_ECFG, ecfg);
}
