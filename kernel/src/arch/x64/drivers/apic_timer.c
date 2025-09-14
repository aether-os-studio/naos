#include <drivers/kernel_logger.h>
#include <arch/x64/drivers/apic_timer.h>
#include <interrupt/irq_manager.h>
#include <arch/arch.h>
#include <task/task.h>

void apic_timer_handler(uint64_t irq_num, void *data, struct pt_regs *regs)
{
    current_task->jiffies += current_task->priority;
    if (current_cpu_id == 0)
        sched_check_wakeup();
}

void apic_timer_init()
{
    irq_regist_irq(APIC_TIMER_INTERRUPT_VECTOR, apic_timer_handler, APIC_TIMER_INTERRUPT_VECTOR - 32, NULL, &apic_controller, "APIC TIMER");
}
