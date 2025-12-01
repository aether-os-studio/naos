#include <libs/aether/input.h>
#include <mod/dlinker.h>

extern dev_input_event_t *kb_input_event;
extern dev_input_event_t *mouse_input_event;

void set_kb_input_event(dev_input_event_t *event) { kb_input_event = event; }
EXPORT_SYMBOL(set_kb_input_event);
void set_mouse_input_event(dev_input_event_t *event) {
    mouse_input_event = event;
}
EXPORT_SYMBOL(set_mouse_input_event);

EXPORT_SYMBOL(regist_input_dev);

EXPORT_SYMBOL(kb_event_bit);
EXPORT_SYMBOL(mouse_event_bit);
