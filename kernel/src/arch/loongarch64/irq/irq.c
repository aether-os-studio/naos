#include <arch/loongarch64/csr.h>
#include <arch/loongarch64/irq/irq.h>

void arch_enable_interrupt() { csr_set(LOONGARCH_CSR_CRMD, 1UL << 2); }
void arch_disable_interrupt() { csr_clear(LOONGARCH_CSR_CRMD, 1UL << 2); }
bool arch_interrupt_enabled() {
    return csr_read(LOONGARCH_CSR_CRMD) & (1UL << 2);
}

void irq_init() {}
