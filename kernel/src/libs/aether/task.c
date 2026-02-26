#include <libs/aether/task.h>
#include <mod/dlinker.h>

#if defined(__x86_64__)
EXPORT_SYMBOL(lapic_id);
#endif

EXPORT_SYMBOL(schedule);
EXPORT_SYMBOL(arch_get_current);

EXPORT_SYMBOL(task_block);
EXPORT_SYMBOL(task_unblock);

EXPORT_SYMBOL(task_create);
EXPORT_SYMBOL(task_exit_inner);
EXPORT_SYMBOL(task_exit);

extern bool can_schedule;
void enable_scheduler() { can_schedule = true; }
void disable_scheduler() { can_schedule = false; }

EXPORT_SYMBOL(enable_scheduler);
EXPORT_SYMBOL(disable_scheduler);
