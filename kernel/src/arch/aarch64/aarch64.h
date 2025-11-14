#pragma once

#define ARCH_MAX_IRQ_NUM 1020

#include "arch/aarch64/drivers/chars/keyboard.h"
#include "arch/aarch64/drivers/chars/mouse.h"
#include "arch/aarch64/drivers/chars/serial.h"
#include "arch/aarch64/drivers/gic.h"
#include "arch/aarch64/drivers/timer.h"
#include "arch/aarch64/drivers/pci/pci-brcmstb.h"
#include "arch/aarch64/irq/ptrace.h"
#include "arch/aarch64/irq/irq.h"
#include "arch/aarch64/mm/arch.h"
#include "arch/aarch64/task/arch_context.h"
#include "arch/aarch64/smp/smp.h"
#include "arch/aarch64/syscall/nr.h"
#include "arch/aarch64/syscall/cpu_info.h"
#include "arch/aarch64/syscall/syscall.h"
#include "arch/aarch64/time/time.h"
#include "mm/page_table.h"

void arch_early_init();
void arch_init();
void arch_init_after_thread();
void arch_input_dev_init();

static inline void arch_pause() { asm volatile("nop"); }

static inline void arch_wait_for_interrupt() { asm volatile("wfi"); }
