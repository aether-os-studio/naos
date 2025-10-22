#include <libs/klibc.h>
#include <libs/keys.h>
#include <fs/vfs/dev.h>
#include <fs/fs_syscall.h>

// Very bare bones, and basic keyboard driver
// Copyright (C) 2024 Panagiotis

char character_table[140] = {
    0,    27,   '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',  '9',  '0',
    '-',  '=',  0,    9,    'q',  'w',  'e',  'r',  't',  'y',  'u',  'i',
    'o',  'p',  '[',  ']',  0,    0,    'a',  's',  'd',  'f',  'g',  'h',
    'j',  'k',  'l',  ';',  '\'', '`',  0,    '\\', 'z',  'x',  'c',  'v',
    'b',  'n',  'm',  ',',  '.',  '/',  0,    '*',  0,    ' ',  0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0x1B, 0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0x0E, 0x1C, 0,    0,    0,
    0,    0,    0,    0,    0,    '/',  0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0,
    0,    0,    0,    0,    0,    0,    0,    0x2C,
};

char shifted_character_table[140] = {
    0,    27,   '!',  '@',  '#',  '$',  '%',  '^',  '&',  '*',  '(',  ')',
    '_',  '+',  0,    9,    'Q',  'W',  'E',  'R',  'T',  'Y',  'U',  'I',
    'O',  'P',  '{',  '}',  0,    0,    'A',  'S',  'D',  'F',  'G',  'H',
    'J',  'K',  'L',  ':',  '"',  '~',  0,    '|',  'Z',  'X',  'C',  'V',
    'B',  'N',  'M',  '<',  '>',  '?',  0,    '*',  0,    ' ',  0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0x1B, 0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0x0E, 0x1C, 0,    0,    0,
    0,    0,    0,    0,    0,    '?',  0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0,
    0,    0,    0,    0,    0,    0,    0,    0x2C,
};

extern dev_input_event_t *kb_input_event;

void kb_evdev_generate(uint8_t code, bool pressed) {
    if (!kb_input_event || !kb_input_event->timesOpened)
        return;

    struct timespec now;
    sys_clock_gettime(kb_input_event->clock_id, (uint64_t)&now, 0);

    bool clicked = pressed;

    // bool oldstate = (evdevInternal[index / 8] & (1 << (index % 8))) != 0;
    // if (!oldstate && clicked) {
    //     input_generate_event(kb_event, EV_KEY, evdevCode, 1, now.tv_sec,
    //                          now.tv_nsec / 1000);
    // } else if (oldstate && clicked) {
    //     input_generate_event(kb_event, EV_KEY, evdevCode, 2, now.tv_sec,
    //                          now.tv_nsec / 1000);
    // } else if (oldstate && !clicked) {
    //     input_generate_event(kb_event, EV_KEY, evdevCode, 0, now.tv_sec,
    //                          now.tv_nsec / 1000);
    // }
    input_generate_event(kb_input_event, EV_KEY, code, clicked ? 1 : 0,
                         now.tv_sec, now.tv_nsec / 1000);
    input_generate_event(kb_input_event, EV_SYN, SYN_REPORT, 0, now.tv_sec,
                         now.tv_nsec / 1000);
}

bool ctrled = false;

bool shifted = false;
bool capsLocked = false;

void handle_kb_event(uint8_t scan_code, bool pressed) {
    kb_evdev_generate(scan_code, pressed);
}

bool clickedLeft = false;
bool clickedRight = false;
bool clickedMiddle = false;

extern dev_input_event_t *mouse_input_event;

void handle_mouse_event(uint8_t flag, int8_t x, int8_t y, int8_t z) {
    if (!mouse_input_event || !mouse_input_event->timesOpened)
        return;

    bool click = (flag & (1 << 0)) != 0;
    bool rclick = (flag & (1 << 1)) != 0;
    bool mclick = (flag & (1 << 2)) != 0;

    struct timespec now;
    sys_clock_gettime(mouse_input_event->clock_id, (uint64_t)&now, 0);

    if (x)
        input_generate_event(mouse_input_event, EV_REL, REL_X, x, now.tv_sec,
                             now.tv_nsec / 1000);
    if (y)
        input_generate_event(mouse_input_event, EV_REL, REL_Y, y, now.tv_sec,
                             now.tv_nsec / 1000);
    if (z)
        input_generate_event(mouse_input_event, EV_REL, REL_WHEEL, z,
                             now.tv_sec, now.tv_nsec / 1000);

    if (clickedLeft && !click)
        input_generate_event(mouse_input_event, EV_KEY, BTN_LEFT, 0, now.tv_sec,
                             now.tv_nsec / 1000);
    if (!clickedLeft && click)
        input_generate_event(mouse_input_event, EV_KEY, BTN_LEFT, 1, now.tv_sec,
                             now.tv_nsec / 1000);

    if (clickedRight && !rclick)
        input_generate_event(mouse_input_event, EV_KEY, BTN_RIGHT, 0,
                             now.tv_sec, now.tv_nsec / 1000);
    if (!clickedRight && rclick)
        input_generate_event(mouse_input_event, EV_KEY, BTN_RIGHT, 1,
                             now.tv_sec, now.tv_nsec / 1000);

    if (clickedMiddle && !mclick)
        input_generate_event(mouse_input_event, EV_KEY, BTN_MIDDLE, 0,
                             now.tv_sec, now.tv_nsec / 1000);
    if (!clickedMiddle && mclick)
        input_generate_event(mouse_input_event, EV_KEY, BTN_MIDDLE, 1,
                             now.tv_sec, now.tv_nsec / 1000);

    input_generate_event(mouse_input_event, EV_SYN, SYN_REPORT, 0, now.tv_sec,
                         now.tv_nsec / 1000);

    clickedLeft = click;
    clickedRight = rclick;
    clickedMiddle = mclick;
}
