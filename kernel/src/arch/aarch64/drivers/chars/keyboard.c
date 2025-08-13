#include <arch/aarch64/drivers/chars/keyboard.h>
#include <arch/arch.h>
#include <task/task.h>

static char *kbBuff = NULL;
static uint32_t kbCurr = 0;
static uint32_t kbMax = 0;
static task_t *kb_task = NULL;

bool task_read(task_t *task, char *buff, uint32_t limit, bool change_state)
{
    while (kbBuff != NULL)
    {
        arch_pause();
    }

    kbBuff = buff;
    kbCurr = 0;
    kbMax = limit;
    kb_task = task;

    if (change_state)
        task->state = TASK_READING_STDIO;

    return true;
}

void kb_reset()
{
    kbBuff = NULL;
    kbCurr = 0;
    kbMax = 0;
    kb_task = NULL;
}

void kb_finalise_stream()
{
    task_t *task = kb_task;
    if (task)
    {
        task->tmp_rec_v = kbCurr;
        task_unblock(task, EOK);
    }
    kb_reset();
}

void kb_char(task_t *task, char ch)
{
    if (task->term.c_lflag & ECHO)
        printk("%c", ch);
    if (kbCurr < kbMax)
        kbBuff[kbCurr++] = ch;
    if (!(task->term.c_lflag & ICANON))
        kb_finalise_stream();
}

void push_kb_char(char ch)
{
    if (!kb_task || !kbBuff)
        return;

    if (ch == '\b')
    {
        if (kb_task->term.c_lflag & ICANON && kbCurr > 0)
        {
            uint32_t back_steps = (kbCurr >= 3 &&
                                   kbBuff[kbCurr - 3] == '\x1b' &&
                                   kbBuff[kbCurr - 2] == '[')
                                      ? 3
                                      : 1;

            kbCurr = (kbCurr >= back_steps) ? kbCurr - back_steps : 0;
            memset(&kbBuff[kbCurr], 0, back_steps);
        }
        else if (!(kb_task->term.c_lflag & ICANON))
            kb_char(kb_task, ch);
    }
    else if (ch == '\n')
    {
        if (kb_task->term.c_lflag & ICANON)
            kb_finalise_stream();
        else
            kb_char(kb_task, ch);
    }
    else
    {
        kb_char(kb_task, ch);
    }

    if (kb_task->state == TASK_READING_STDIO)
        kb_task->state = TASK_READY;
}

size_t kb_event_bit(void *data, uint64_t request, void *arg)
{
    return 0;
}
