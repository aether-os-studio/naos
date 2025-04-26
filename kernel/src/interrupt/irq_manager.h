#pragma once

#include <arch/arch.h>

typedef struct NA_irq_controller
{
    NA_err_t (*unmask)(uint64_t irq);
    NA_err_t (*mask)(uint64_t irq);
    NA_err_t (*ack)(uint64_t irq);
} NA_irq_controller_t;

typedef struct NA_irq_action
{
    char *name;
    void *data;
    NA_irq_controller_t *irq_controller;
    void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs);
} NA_irq_action_t;

void irq_regist_irq(uint64_t irq_num, void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs), void *data, NA_irq_controller_t *controller, char *name);
