#include <libs/klibc.h>
#include <arch/arch.h>
#include <task/task.h>

void handle_exception_c(struct pt_regs *regs, uint64_t cause);
void handle_interrupt_c(struct pt_regs *regs, uint64_t cause);

spinlock_t dump_lock = {0};

void dump_registers(struct pt_regs *regs) {
    spin_lock(&dump_lock);

    // 通用寄存器部分
    printk("ra: 0x%016lx  sp: 0x%016lx\n", regs->ra, regs->sp);
    printk("gp: 0x%016lx  tp: 0x%016lx\n", regs->gp, regs->tp);
    printk("t0: 0x%016lx  t1: 0x%016lx\n", regs->t0, regs->t1);
    printk("t2: 0x%016lx  s0: 0x%016lx\n", regs->t2, regs->s0);
    printk("s1: 0x%016lx  a0: 0x%016lx\n", regs->s1, regs->a0);
    printk("a1: 0x%016lx  a2: 0x%016lx\n", regs->a1, regs->a2);
    printk("a3: 0x%016lx  a4: 0x%016lx\n", regs->a3, regs->a4);
    printk("a5: 0x%016lx  a6: 0x%016lx\n", regs->a5, regs->a6);
    printk("a7: 0x%016lx  s2: 0x%016lx\n", regs->a7, regs->s2);
    printk("s3: 0x%016lx  s4: 0x%016lx\n", regs->s3, regs->s4);
    printk("s5: 0x%016lx  s6: 0x%016lx\n", regs->s5, regs->s6);
    printk("s7: 0x%016lx  s8: 0x%016lx\n", regs->s7, regs->s8);
    printk("s9: 0x%016lx  s10: 0x%016lx\n", regs->s9, regs->s10);
    printk("s11: 0x%016lx  t3: 0x%016lx\n", regs->s11, regs->t3);
    printk("t4: 0x%016lx  t5: 0x%016lx\n", regs->t4, regs->t5);
    printk("t6: 0x%016lx\n", regs->t6); // 最后一个单独一行

    // CSR 寄存器部分
    printk("epc: 0x%016lx  sstatus: 0x%016lx\n", regs->epc, regs->sstatus);
    printk("stval: 0x%016lx\n", regs->stval);

    spin_unlock(&dump_lock);
}

// 异常处理函数
void handle_trap_c(struct pt_regs *regs) {
    uint64_t is_interrupt = csr_read(scause) & (1UL << 63);
    uint64_t cause_code = csr_read(scause) & 0x7FFFFFFFFFFFFFFF;

    if (is_interrupt) {
        handle_interrupt_c(regs, cause_code);
    } else {
        if (cause_code != 8 && cause_code != 11) {
            printk("Exception occurred:\n");

            dump_registers(regs);
        }

        handle_exception_c(regs, cause_code);
    }
}

extern void syscall_handler(struct pt_regs *regs);

void handle_syscall(struct pt_regs *regs) { syscall_handler(regs); }

void handle_exception_c(struct pt_regs *regs, uint64_t cause) {
    switch (cause) {
    case 2: // Illegal instruction
        printk("Illegal instruction at PC: 0x%lx\n", regs->epc);
        // 跳过非法指令
        while (1)
            arch_pause();
        break;

    case 3: // Breakpoint
        printk("Breakpoint at PC: 0x%lx\n", regs->epc);
        // 跳过断点指令
        while (1)
            arch_pause();
        break;

    case 8: // ecall
        handle_syscall(regs);
        regs->epc += 4;
        break;

    case 11: // scall
        handle_syscall(regs);
        regs->epc += 4;
        break;

    default:
        printk("Unhandled exception: %lu\n", cause);
        while (1)
            arch_pause();
        break;
    }
}

extern void riscv64_timer_handler(struct pt_regs *regs);

extern void do_irq(struct pt_regs *regs, uint64_t irq_num);

extern bool can_schedule;

void handle_interrupt_c(struct pt_regs *regs, uint64_t cause) {
    switch (cause) {
    case 5: // timer interrupt
        riscv64_timer_handler(regs);

        sbi_set_timer(get_timer() + TIMER_FREQ / SCHED_HZ);

        if (can_schedule) {
            schedule();
        }

        break;

    default:
        do_irq(regs, cause);
        break;
    }
}

extern int init_trap_vector();

// 安全的初始化函数
int trap_init(void) {
    // 调用汇编初始化函数
    int result = init_trap_vector();
    if (result != 0) {
        printk("Failed to initialize trap vector: %d\n", result);
        return result;
    }

    // 使能机器模式中断
    uint64_t sstatus;
    asm volatile("csrr %0, sstatus" : "=r"(sstatus));
    sstatus |= (1 << 3); // 设置SIE位
    asm volatile("csrw sstatus, %0" ::"r"(sstatus));

    return 0;
}
