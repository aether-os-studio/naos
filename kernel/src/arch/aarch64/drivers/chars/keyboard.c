#include <arch/aarch64/drivers/chars/keyboard.h>
#include <task/task.h>
#include <fs/vfs/dev.h>
#include <libs/keys.h>

dev_input_event_t *kb_input_event = NULL;

size_t kb_event_bit(void *data, uint64_t request, void *arg) { return 0; }
