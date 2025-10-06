#include "irq.h"
#include "arch/riscv64/io.h"

void arch_enable_interrupt() { csr_set(sstatus, (1 << 1)); /* SIE */ }

void arch_disable_interrupt() { csr_clear(sstatus, (1 << 1)); /* SIE */ }
