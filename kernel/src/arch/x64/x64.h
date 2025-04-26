#pragma once

#include "drivers/serial.h"
#include "mm/page_table.h"
#include "irq/ptrace.h"
#include "irq/asm.h"
#include "irq/gate.h"
#include "irq/trap.h"

void NA_arch_early_init();
