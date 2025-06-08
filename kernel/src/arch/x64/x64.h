#pragma once

#define ARCH_MAX_IRQ_NUM 256

#include "asm.h"
#include "acpi/acpi.h"
#include "mm/arch.h"
#include "irq/ptrace.h"
#include "irq/gate.h"
#include "irq/trap.h"
#include "irq/irq.h"
#include "drivers/serial.h"
#include "drivers/apic_timer.h"
#include "drivers/chars/ps2_kbd.h"
#include "drivers/chars/ps2_mouse.h"
#include "drivers/msi_arch.h"
#include "task/arch_context.h"
#include "task/fsgsbase.h"
#include "syscall/nr.h"
#include "syscall/syscall.h"
#include "time/time.h"

void arch_early_init();
void arch_init();
void arch_input_dev_init();

static inline void arch_pause()
{
    asm volatile("pause");
}
