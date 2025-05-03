#include <arch/aarch64/drivers/chars/keyboard.h>
#include <arch/aarch64/drivers/serial.h>

uint8_t get_keyboard_input()
{
    return serial_read();
}
