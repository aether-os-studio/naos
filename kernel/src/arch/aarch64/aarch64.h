#pragma once

#define ARCH_MAX_IRQ_NUM 1020

#include "acpi/acpi.h"
#include "acpi/gic.h"
#include "drivers/serial.h"
#include "drivers/chars/keyboard.h"
#include "drivers/chars/mouse.h"
#include "mm/page_table.h"
#include "irq/ptrace.h"
#include "irq/irq.h"
#include "mm/page_table.h"
#include "arch/aarch64/task/arch_context.h"
#include "smp/smp.h"
#include "syscall/nr.h"
#include "syscall/syscall.h"
#include "time/time.h"

void arch_early_init();
void arch_init();
void arch_input_dev_init();

static inline void arch_pause()
{
    __asm__ __volatile__("nop");
}
