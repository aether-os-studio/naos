#include <drivers/kernel_logger.h>
#include <arch/x64/drivers/apic_timer.h>
#include <interrupt/irq_manager.h>
#include <task/task.h>

void apic_timer_handler(uint64_t irq_num, void *data, struct pt_regs *regs)
{
    current_task->jiffies++;

    arch_task_switch_to(regs, current_task, task_search(TASK_READY, current_task->cpu_id));
}

void apic_timer_init()
{
    irq_regist_irq(APIC_TIMER_INTERRUPT_VECTOR, apic_timer_handler, NULL, &apic_controller, "APIC TIMER");
}
