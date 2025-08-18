#pragma once

#define ARCH_MAX_IRQ_NUM 1024 // TODO

#include "arch/loongarch64/acpi/acpi.h"
#include "arch/loongarch64/drivers/char/kb.h"
#include "arch/loongarch64/drivers/serial.h"
#include "arch/loongarch64/irq/irq.h"
#include "arch/loongarch64/irq/ptrace.h"
#include "arch/loongarch64/mm/arch.h"
#include "arch/loongarch64/syscall/nr.h"
#include "arch/loongarch64/task/arch_context.h"
#include "arch/loongarch64/time/time.h"

void arch_early_init();

void arch_init();

void arch_input_dev_init();

static inline void arch_pause()
{
    asm volatile(
        "idle 0\n" ::: "memory");
}
