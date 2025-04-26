#include <drivers/kernel_logger.h>
#include <arch/x64/drivers/apic_timer.h>
#include <interrupt/irq_manager.h>

void apic_timer_handler(uint64_t irq_num, void *data, struct pt_regs *regs)
{
}

void apic_timer_init()
{
    irq_regist_irq(APIC_TIMER_INTERRUPT_VECTOR, apic_timer_handler, NULL, &apic_controller, "APIC TIMER");
}
