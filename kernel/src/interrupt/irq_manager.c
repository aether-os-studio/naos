#include <interrupt/irq_manager.h>
#include <drivers/kernel_logger.h>

NA_irq_action_t actions[NA_ARCH_MAX_IRQ_NUM];

void NA_do_irq(struct pt_regs *regs, uint64_t irq_num)
{
    NA_irq_action_t *action = &actions[irq_num];

    if (action->handler != NULL)
    {
        action->handler(irq_num, action->data, regs);
    }
    else
    {
        NA_printk("Intr vector [%d] does not have a handler\n", irq_num);
    }

    if (action->irq_controller != NULL && action->irq_controller->ack != NULL)
    {
        action->irq_controller->ack(irq_num);
    }
    else
    {
        NA_printk("Intr vector [%d] does not have a ack\n", irq_num);
    }
}

void irq_regist_irq(uint64_t irq_num, void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs), void *data, NA_irq_controller_t *controller, char *name)
{
    NA_irq_action_t *action = &actions[irq_num];

    action->handler = handler;
    action->data = data;
    action->irq_controller = controller;
    action->name = name;
}
