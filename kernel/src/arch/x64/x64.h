#pragma once

#define NA_ARCH_MAX_IRQ_NUM 256

#include "acpi/acpi.h"
#include "mm/page_table.h"
#include "irq/ptrace.h"
#include "irq/asm.h"
#include "irq/gate.h"
#include "irq/trap.h"
#include "irq/irq.h"
#include "drivers/serial.h"
#include "drivers/apic_timer.h"

void NA_arch_early_init();
void NA_arch_init();
