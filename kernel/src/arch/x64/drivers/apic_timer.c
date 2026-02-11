#include <drivers/kernel_logger.h>
#include <arch/x64/drivers/apic_timer.h>
#include <irq/irq_manager.h>
#include <arch/arch.h>
#include <task/task.h>

void apic_timer_handler(uint64_t irq_num, void *data, struct pt_regs *regs) {
}

void apic_timer_init() {
    irq_regist_irq(APIC_TIMER_INTERRUPT_VECTOR, apic_timer_handler, 0, NULL,
                   &apic_controller, "Apic timer", IRQ_FLAGS_LAPIC);
}
