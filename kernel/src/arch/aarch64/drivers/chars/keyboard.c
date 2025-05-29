#include <arch/aarch64/drivers/chars/keyboard.h>
#include <arch/arch.h>
#include <task/task.h>

bool task_read(task_t *task, char *buff, uint32_t limit, bool change_state)
{
    uint8_t data = 0;
    do
    {
        data = get_keyboard_input();

        arch_pause();
    } while (data == 0);

    *(uint8_t *)buff = data;

    return true;
}

uint8_t get_keyboard_input()
{
    return get_keyboard_input_queue();
}

size_t kb_event_bit(void *data, uint64_t request, void *arg)
{
    return 0;
}
