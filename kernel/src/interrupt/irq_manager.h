#pragma once

#include <arch/arch.h>

typedef struct irq_controller
{
    err_t (*unmask)(uint64_t irq);
    err_t (*mask)(uint64_t irq);
    err_t (*ack)(uint64_t irq);
} irq_controller_t;

typedef struct irq_action
{
    char *name;
    void *data;
    irq_controller_t *irq_controller;
    void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs);
} irq_action_t;

void irq_regist_irq(uint64_t irq_num, void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs), void *data, irq_controller_t *controller, char *name);
