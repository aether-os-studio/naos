#pragma once

#include <interrupt/irq_manager.h>

#define TIMER_IRQ 30

extern irq_controller_t gic_controller;

extern void gic_init();
extern void gic_init_percpu(uint64_t cpu_id);

extern err_t gic_enable_interrupt(uint64_t eoi);
extern err_t gic_send_eoi(uint64_t eoi);
