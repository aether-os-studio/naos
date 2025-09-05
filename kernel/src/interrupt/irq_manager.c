#include <interrupt/irq_manager.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>
#include <task/task.h>
#include <mm/bitmap.h>

irq_action_t actions[ARCH_MAX_IRQ_NUM];

extern bool can_schedule;

void do_irq(struct pt_regs *regs, uint64_t irq_num)
{
    irq_action_t *action = &actions[irq_num];

    if (action->handler)
    {
        action->handler(irq_num, action->data, regs);
    }
    else
    {
        printk("Intr vector [%d] does not have a handler\n", irq_num);
    }

    if (action->irq_controller && action->irq_controller->ack)
    {
        action->irq_controller->ack(irq_num);
    }
    else
    {
        printk("Intr vector [%d] does not have an ack\n", irq_num);
    }

    if ((irq_num == ARCH_TIMER_IRQ) && can_schedule)
    {
        arch_task_switch_to(regs, current_task, task_search(TASK_READY, current_task->cpu_id));
    }
}

void irq_regist_irq(uint64_t irq_num, void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs), uint64_t arg, void *data, irq_controller_t *controller, char *name)
{
    irq_action_t *action = &actions[irq_num];

    action->handler = handler;
    action->data = data;
    action->irq_controller = controller;
    action->name = name;

    if (action->irq_controller && action->irq_controller->install)
    {
        action->irq_controller->install(irq_num, arg);
    }

    if (action->irq_controller && action->irq_controller->unmask)
    {
        action->irq_controller->unmask(irq_num);
    }
}

// true: used
// false: unused
Bitmap irq_bitmap;
const int irq_bitmap_size = (ARCH_MAX_IRQ_NUM + 7) / 8;

void irq_manager_init()
{
    bitmap_init(&irq_bitmap, malloc(irq_bitmap_size), irq_bitmap_size);
    bitmap_set_range(&irq_bitmap, 0, IRQ_ALLOCATE_NUM_BASE, true);
}

int irq_allocate_irqnum()
{
    int idx = bitmap_find_range_from(&irq_bitmap, 1, false, IRQ_ALLOCATE_NUM_BASE);
    if (idx < 0)
    {
        printk("Failed to allocate irq");
    }
    bitmap_set(&irq_bitmap, idx, true);
    return idx;
}

void irq_deallocate_irqnum(int irq_num)
{
    bitmap_set(&irq_bitmap, irq_num, false);
}
