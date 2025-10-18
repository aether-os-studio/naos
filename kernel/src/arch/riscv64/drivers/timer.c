#include <arch/arch.h>
#include <task/task.h>

/**
 * 初始化单个Hart的定时器
 */
void timer_init_hart(uint32_t hart_id) {
    /* 使能S模式定时器中断 */
    csr_set(sie, (1 << 5)); /* STIE */

    sbi_set_timer(get_timer() + TIMER_FREQ / SCHED_HZ);
}

void riscv64_timer_handler(struct pt_regs *regs) {
    // sched_check_wakeup();
}
