#include "kb.h"
#include <task/task.h>

task_t *kb_task = NULL;

void kb_char(task_t *task, char ch) {}

bool task_read(task_t *task, char *buff, uint32_t limit, bool change_state) {
    return true;
}

void kb_finalise_stream() {}

size_t kb_event_bit(void *data, uint64_t request, void *arg) { return 0; }

size_t mouse_event_bit(void *data, uint64_t request, void *arg) { return 0; }
