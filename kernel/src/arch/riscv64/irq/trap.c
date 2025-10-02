#include <libs/klibc.h>
#include <arch/arch.h>

void handle_exception_c(struct pt_regs *regs, uint64_t cause);
void handle_interrupt_c(struct pt_regs *regs, uint64_t cause);

// 异常处理函数
void handle_trap_c(struct pt_regs *regs) {
    uint64_t is_interrupt = regs->scause & (1UL << 63);
    uint64_t cause_code = regs->scause & 0x7FFFFFFFFFFFFFFF;

    if (is_interrupt) {
        handle_interrupt_c(regs, cause_code);
    } else {
        printk("Exception occurred:\n");
        printk("  PC: 0x%lx\n", regs->sepc);
        printk("  Cause: 0x%lx (%s)\n", regs->scause, "exception");
        printk("  stval: 0x%lx\n", regs->stval);
        printk("  sstatus: 0x%lx\n", regs->sstatus);

        handle_exception_c(regs, cause_code);
    }
}

extern void syscall_handler(struct pt_regs *regs);

void handle_syscall(struct pt_regs *regs) { syscall_handler(regs); }

void handle_exception_c(struct pt_regs *regs, uint64_t cause) {
    switch (cause) {
    case 2: // Illegal instruction
        printk("Illegal instruction at PC: 0x%lx\n", regs->sepc);
        // 跳过非法指令
        while (1)
            arch_pause();
        break;

    case 3: // Breakpoint
        printk("Breakpoint at PC: 0x%lx\n", regs->sepc);
        // 跳过断点指令
        while (1)
            arch_pause();
        break;

    case 11: // Machine ecall
        handle_syscall(regs);
        regs->sepc += 4;
        break;

    default:
        printk("Unhandled exception: %lu\n", cause);
        while (1)
            arch_pause();
        break;
    }
}

extern void riscv64_timer_handler(struct pt_regs *regs);

void handle_interrupt_c(struct pt_regs *regs, uint64_t cause) {
    switch (cause) {
    case 5: // timer interrupt
        riscv64_timer_handler(regs);

        sbi_set_timer(get_timer() + TIMER_FREQ / SCHED_HZ);

        break;

    default:
        printk("Unhandled interrupt: %lu\n", cause);
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
