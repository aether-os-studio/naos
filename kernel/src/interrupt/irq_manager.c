#include <interrupt/irq_manager.h>
#include <drivers/kernel_logger.h>

irq_action_t actions[ARCH_MAX_IRQ_NUM];

void do_irq(struct pt_regs *regs, uint64_t irq_num)
{
    irq_action_t *action = &actions[irq_num];

    if (action->handler != NULL)
    {
        action->handler(irq_num, action->data, regs);
    }
    else
    {
        printk("Intr vector [%d] does not have a handler\n", irq_num);
    }

    if (action->irq_controller != NULL && action->irq_controller->ack != NULL)
    {
        action->irq_controller->ack(irq_num);
    }
    else
    {
        printk("Intr vector [%d] does not have a ack\n", irq_num);
    }
}

void irq_regist_irq(uint64_t irq_num, void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs), void *data, irq_controller_t *controller, char *name)
{
    irq_action_t *action = &actions[irq_num];

    action->handler = handler;
    action->data = data;
    action->irq_controller = controller;
    action->name = name;
}
