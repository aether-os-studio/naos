#include <drivers/kernel_logger.h>
#include <arch/x64/drivers/apic_timer.h>
#include <interrupt/irq_manager.h>
#include <task/task.h>

extern void task_signal();

extern bool can_schedule;

void apic_timer_handler(uint64_t irq_num, void *data, struct pt_regs *regs)
{
    current_task->jiffies++;

    task_signal();

    send_eoi(irq_num);

    if (can_schedule)
    {
        arch_task_switch_to(regs, current_task, task_search(TASK_READY, current_task->cpu_id));
    }
}

void apic_timer_init()
{
    irq_regist_irq(APIC_TIMER_INTERRUPT_VECTOR, apic_timer_handler, APIC_TIMER_INTERRUPT_VECTOR - 32, NULL, &apic_controller, "APIC TIMER");
}
