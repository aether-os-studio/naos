#include <arch/arch.h>

void arch_enable_interrupt() {
    uint64_t crmd = csr_read(LOONGARCH_CSR_CRMD);
    crmd |= CSR_CRMD_IE;
    csr_write(LOONGARCH_CSR_CRMD, crmd);
}

void arch_disable_interrupt() {
    uint64_t crmd = csr_read(LOONGARCH_CSR_CRMD);
    crmd &= ~CSR_CRMD_IE;
    csr_write(LOONGARCH_CSR_CRMD, crmd);
}
