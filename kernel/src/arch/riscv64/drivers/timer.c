#include <arch/arch.h>
#include <task/task.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>

uint64_t timer_freq = TIMER_FREQ;

/**
 * 初始化单个Hart的定时器
 */
void timer_init_hart(uint32_t hart_id) {
    /* 使能S模式定时器中断 */
    csr_set(sie, (1 << 5)); /* STIE */

    uacpi_table rhct_table;
    uacpi_status status =
        uacpi_table_find_by_signature(ACPI_RHCT_SIGNATURE, &rhct_table);
    if (status == UACPI_STATUS_OK) {
        struct acpi_rhct *rhct = rhct_table.ptr;
        timer_freq = rhct->timebase_frequency;
    }

    arch_enable_interrupt();

    sbi_set_timer(get_timer() + timer_freq / SCHED_HZ);
}

void riscv64_timer_handler(struct pt_regs *regs) { sched_check_wakeup(); }
