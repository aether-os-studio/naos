#pragma once

#include <libs/klibc.h>
#include <irq/irq_manager.h>
#include <arch/arch.h>

uint64_t get_cpu_count();

#if defined(__x86_64__)
irq_controller_t *get_apic_controller();
uint64_t get_lapicid_by_cpuid(uint64_t cpuid);
#endif
