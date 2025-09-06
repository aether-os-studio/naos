#pragma once

#include <libs/klibc.h>
#include <interrupt/irq_manager.h>
#include <arch/arch.h>

#if defined(__x86_64__)
irq_controller_t *get_apic_controller();
#endif
