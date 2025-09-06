#include <libs/aether/irq.h>
#include <mod/dlinker.h>

EXPORT_SYMBOL(irq_regist_irq);
EXPORT_SYMBOL(irq_allocate_irqnum);
EXPORT_SYMBOL(irq_deallocate_irqnum);

EXPORT_SYMBOL(arch_enable_interrupt);
EXPORT_SYMBOL(arch_disable_interrupt);

#if defined(__x86_64__)
irq_controller_t *get_apic_controller()
{
    return &apic_controller;
}
EXPORT_SYMBOL(get_apic_controller);
#endif
