#pragma once

#include <arch/x64/acpi/acpi.h>
#include <arch/x64/irq/irq.h>
#include <drivers/block/ahci/hba.h>

enum
{
    KEY_BUTTON_UP = 0x81,
    KEY_BUTTON_DOWN = 0x82,
    KEY_BUTTON_LEFT = 0x83,
    KEY_BUTTON_RIGHT = 0x84,
};

#define PORT_KB_DATA 0x60
#define PORT_KB_STATUS 0x64
#define PORT_KB_CMD 0x64

#define KBCMD_WRITE_CMD 0x60
#define KBCMD_READ_CMD 0x20

#define KB_INIT_MODE 0x47

#define KB_SEND2MOUSE 0xd4
#define MOUSE_EN 0xf4

#define KB_EN_MOUSE_INTFACE 0xa8

#define KBSTATUS_IBF 0x02
#define KBSTATUS_OBF 0x01

#define wait_KB_write() wait_until_expire(!(io_in8(PORT_KB_STATUS) & KBSTATUS_IBF), 1000000)

#define wait_KB_read() wait_until_expire(!(io_in8(PORT_KB_STATUS) & KBSTATUS_OBF), 1000000)

bool kb_is_ocupied();

struct task;
typedef struct task task_t;

bool task_read(task_t *task, char *buff, uint32_t limit, bool change_state);

#define SYN_REPORT 0
#define SYN_CONFIG 1
#define SYN_MT_REPORT 2
#define SYN_DROPPED 3
#define SYN_MAX 0xf
#define SYN_CNT (SYN_MAX + 1)

#define SCANCODE_ENTER 28
#define SCANCODE_BACK 14
#define SCANCODE_SHIFT 42
#define SCANCODE_CAPS 58
#define SCANCODE_UP 0x48

#define CHARACTER_ENTER '\n'
#define CHARACTER_BACK '\b'

size_t kb_event_bit(void *data, uint64_t request, void *arg);

void kbd_init();

void kb_char(task_t *task, char out);

extern char character_table[];
extern char shifted_character_table[];

void push_kb_char(char c);
