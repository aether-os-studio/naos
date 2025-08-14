#include <libs/aether/evdev.h>
#include <mod/dlinker.h>

extern task_t *kb_task;

task_t *get_kb_task()
{
    return kb_task;
}

EXPORT_SYMBOL(handle_kb_event);
EXPORT_SYMBOL(get_kb_task);

EXPORT_SYMBOL(kb_char);
EXPORT_SYMBOL(kb_finalise_stream);
