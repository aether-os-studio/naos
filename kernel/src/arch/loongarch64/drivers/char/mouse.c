
#include <arch/loongarch64/drivers/char/mouse.h>
#include <task/task.h>
#include <fs/vfs/dev.h>
#include <libs/keys.h>

dev_input_event_t *mouse_input_event = NULL;

size_t mouse_event_bit(void *data, uint64_t request, void *arg) { return 0; }
