#include "kb.h"
#include <task/task.h>
#include <fs/vfs/dev.h>

dev_input_event_t *kb_input_event = NULL;
dev_input_event_t *mouse_input_event = NULL;

size_t kb_event_bit(void *data, uint64_t request, void *arg) { return 0; }

size_t mouse_event_bit(void *data, uint64_t request, void *arg) { return 0; }
