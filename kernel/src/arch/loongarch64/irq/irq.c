#include <arch/loongarch64/csr.h>
#include <arch/loongarch64/irq/irq.h>
#include <arch/loongarch64/mm/arch.h>
#include <arch/loongarch64/time/time.h>
#include <arch/loongarch64/syscall/syscall.h>
#include <irq/irq_manager.h>
#include <mm/fault.h>
#include <mm/vma.h>
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

static void loongarch64_dump_regs(const struct pt_regs *regs,
                                  const char *reason) {
    if (!regs)
        return;

    printk("======== LoongArch64 register dump ========\n");
    if (reason)
        printk("%s\n", reason);

    if (current_task) {
        printk(
            "current_task->pid = %lu, cpu_id = %d, current_task->name = %s\n",
            current_task->pid, current_task->cpu_id, current_task->name);
    }

    printk(" PC = %#018lx,  RA = %#018lx,  SP = %#018lx, USP = %#018lx\n",
           regs->pc, regs->ra, regs->sp, regs->usp);
    printk(" TP = %#018lx,  GP = %#018lx,  FP = %#018lx, R21 = %#018lx\n",
           regs->tp, regs->gp, regs->fp, regs->r21);

    printk(" A0 = %#018lx,  A1 = %#018lx,  A2 = %#018lx,  A3 = %#018lx\n",
           regs->a0, regs->a1, regs->a2, regs->a3);
    printk(" A4 = %#018lx,  A5 = %#018lx,  A6 = %#018lx,  A7 = %#018lx\n",
           regs->a4, regs->a5, regs->a6, regs->a7);

    printk(" T0 = %#018lx,  T1 = %#018lx,  T2 = %#018lx,  T3 = %#018lx\n",
           regs->t0, regs->t1, regs->t2, regs->t3);
    printk(" T4 = %#018lx,  T5 = %#018lx,  T6 = %#018lx,  T7 = %#018lx\n",
           regs->t4, regs->t5, regs->t6, regs->t7);
    printk(" T8 = %#018lx\n", regs->t8);

    printk(" S0 = %#018lx,  S1 = %#018lx,  S2 = %#018lx,  S3 = %#018lx\n",
           regs->s0, regs->s1, regs->s2, regs->s3);
    printk(" S4 = %#018lx,  S5 = %#018lx,  S6 = %#018lx,  S7 = %#018lx\n",
           regs->s4, regs->s5, regs->s6, regs->s7);
    printk(" S8 = %#018lx\n", regs->s8);

    printk("PRMD = %#018lx, ESTAT = %#018lx, BADV = %#018lx, syscallno = "
           "%#018lx\n",
           regs->csr_prmd, regs->csr_estat, regs->csr_badv, regs->syscallno);
    printk("======== LoongArch64 register dump end ========\n");
}

static void loongarch64_unhandled_trap(struct pt_regs *regs) {
    printk("Unhandled LoongArch trap: estat=%#018lx era=%#018lx badv=%#018lx "
           "prmd=%#018lx\n",
           regs->csr_estat, regs->pc, regs->csr_badv, regs->csr_prmd);
    loongarch64_dump_regs(regs, "Unhandled LoongArch trap");
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
    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
    spin_lock(&mgr->lock);
    vma_t *vma = vma_find(mgr, fault_addr);
    if (vma) {
        printk("Fault VMA: [%#018lx, %#018lx) vm_flags=%#018lx "
               "vm_type=%d name=%s\n",
               vma->vm_start, vma->vm_end, vma->vm_flags, vma->vm_type,
               vma->vm_name ? vma->vm_name : "(null)");
    } else {
        printk("Fault VMA: none\n");
    }
    spin_unlock(&mgr->lock);
    loongarch64_dump_regs(regs, "Unresolved LoongArch page fault");

    task_exit(128 + SIGSEGV);
}

static bool loongarch64_handle_disabled_fp_simd(struct pt_regs *regs,
                                                uint64_t ecode) {
    if (!loongarch64_user_mode_frame(regs))
        return false;

    switch (ecode) {
    case LOONGARCH_ECODE_FPD:
        csr_set(LOONGARCH_CSR_EUEN, LOONGARCH_EUEN_FPE);
        return true;
    case LOONGARCH_ECODE_SXD:
        csr_set(LOONGARCH_CSR_EUEN, LOONGARCH_EUEN_FPE | LOONGARCH_EUEN_SXE);
        return true;
    default:
        return false;
    }
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

    if (loongarch64_handle_disabled_fp_simd(regs, ecode)) {
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
