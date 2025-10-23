#include <libs/aether/irq.h>
#include <mod/dlinker.h>

EXPORT_SYMBOL(irq_regist_irq);
EXPORT_SYMBOL(irq_allocate_irqnum);
EXPORT_SYMBOL(irq_deallocate_irqnum);

EXPORT_SYMBOL(arch_enable_interrupt);
EXPORT_SYMBOL(arch_disable_interrupt);

uint64_t get_cpu_count() { return cpu_count; }
EXPORT_SYMBOL(get_cpu_count);

#if defined(__x86_64__)
irq_controller_t *get_apic_controller() { return &apic_controller; }
EXPORT_SYMBOL(get_apic_controller);
extern uint32_t cpuid_to_lapicid[MAX_CPU_NUM];
uint64_t get_lapicid_by_cpuid(uint64_t cpuid) {
    return cpuid_to_lapicid[cpuid];
}
EXPORT_SYMBOL(get_lapicid_by_cpuid);
EXPORT_SYMBOL(get_cpuid_by_lapic_id);
EXPORT_SYMBOL(lapic_id);
#endif
