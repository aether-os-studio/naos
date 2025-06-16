#include <libs/klibc.h>
#include <libs/keys.h>
#include <fs/vfs/dev.h>

// Very bare bones, and basic keyboard driver
// Copyright (C) 2024 Panagiotis

char character_table[140] = {
    0,
    27,
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '0',
    '-',
    '=',
    0,
    9,
    'q',
    'w',
    'e',
    'r',
    't',
    'y',
    'u',
    'i',
    'o',
    'p',
    '[',
    ']',
    0,
    0,
    'a',
    's',
    'd',
    'f',
    'g',
    'h',
    'j',
    'k',
    'l',
    ';',
    '\'',
    '`',
    0,
    '\\',
    'z',
    'x',
    'c',
    'v',
    'b',
    'n',
    'm',
    ',',
    '.',
    '/',
    0,
    '*',
    0,
    ' ',
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x1B,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x0E,
    0x1C,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    '/',
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x2C,
};

char shifted_character_table[140] = {
    0,
    27,
    '!',
    '@',
    '#',
    '$',
    '%',
    '^',
    '&',
    '*',
    '(',
    ')',
    '_',
    '+',
    0,
    9,
    'Q',
    'W',
    'E',
    'R',
    'T',
    'Y',
    'U',
    'I',
    'O',
    'P',
    '{',
    '}',
    0,
    0,
    'A',
    'S',
    'D',
    'F',
    'G',
    'H',
    'J',
    'K',
    'L',
    ':',
    '"',
    '~',
    0,
    '|',
    'Z',
    'X',
    'C',
    'V',
    'B',
    'N',
    'M',
    '<',
    '>',
    '?',
    0,
    '*',
    0,
    ' ',
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x1B,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x0E,
    0x1C,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    '?',
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x2C,
};

const uint8_t evdevTable[89] = {
    0,
    KEY_ESC,
    KEY_1,
    KEY_2,
    KEY_3,
    KEY_4,
    KEY_5,
    KEY_6,
    KEY_7,
    KEY_8,
    KEY_9,
    KEY_0,
    KEY_MINUS,
    KEY_EQUAL,
    KEY_BACKSPACE,
    KEY_TAB,
    KEY_Q,
    KEY_W,
    KEY_E,
    KEY_R,
    KEY_T,
    KEY_Y,
    KEY_U,
    KEY_I,
    KEY_O,
    KEY_P,
    KEY_LEFTBRACE,
    KEY_RIGHTBRACE,
    KEY_ENTER,
    KEY_LEFTCTRL,
    KEY_A,
    KEY_S,
    KEY_D,
    KEY_F,
    KEY_G,
    KEY_H,
    KEY_J,
    KEY_K,
    KEY_L,
    KEY_SEMICOLON,
    KEY_APOSTROPHE,
    KEY_GRAVE,
    KEY_LEFTSHIFT,
    KEY_BACKSLASH,
    KEY_Z,
    KEY_X,
    KEY_C,
    KEY_V,
    KEY_B,
    KEY_N,
    KEY_M,
    KEY_COMMA,
    KEY_DOT,
    KEY_SLASH,
    KEY_RIGHTSHIFT,
    KEY_KPASTERISK,
    KEY_LEFTALT,
    KEY_SPACE,
    KEY_CAPSLOCK,
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_NUMLOCK,
    KEY_SCROLLLOCK,
    KEY_KP7,
    KEY_UP, // KEY_KP8
    KEY_KP9,
    KEY_KPMINUS,
    KEY_LEFT, // KEY_KP4
    KEY_KP5,
    KEY_RIGHT, // KEY_KP6
    KEY_KPPLUS,
    KEY_KP1,
    KEY_DOWN, // KEY_KP2
    KEY_KP3,
    KEY_INSERT, // KEY_KP0
    KEY_DELETE, // KEY_KPDOT
    0,
    0,
    0,
    KEY_F11,
    KEY_F12,
};

// it's just a bitmap to accurately track press/release/repeat ops
#define EVDEV_INTERNAL_SIZE (((sizeof(evdevTable) / sizeof(evdevTable[0]) + 7) / 8))

uint8_t evdevInternal[EVDEV_INTERNAL_SIZE] = {0};

uint8_t lastPressed = 0;

dev_input_event_t *kb_event = NULL;

void kb_evdev_generate(uint8_t raw)
{
    if (!kb_event)
        return;

    uint8_t index = 0;
    bool clicked = false;
    if (raw <= 0x58)
    {
        clicked = true;
        index = raw;
    }
    else if (raw <= 0xD8)
    {
        clicked = false;
        index = raw - 0x80;
    }
    else
        return;

    if (index > 88)
        return;
    uint8_t evdevCode = evdevTable[index];
    if (!evdevCode)
        return;

    bool oldstate = evdevInternal[index / 8];
    if (!oldstate && clicked)
    {
        // was not clicked previously, now clicked (click)
        input_generate_event(kb_event, EV_KEY, evdevCode, 1);
        lastPressed = evdevCode;
    }
    else if (oldstate && clicked)
    {
        // was clicked previously, now clicked (repeat)
        if (evdevCode != lastPressed)
            return; // no need to re-set it on the bitmap
        input_generate_event(kb_event, EV_KEY, evdevCode, 2);
    }
    else if (oldstate && !clicked)
    {
        // was clicked previously, now not clicked (release)
        input_generate_event(kb_event, EV_KEY, evdevCode, 0);
    }
    input_generate_event(kb_event, EV_SYN, SYN_REPORT, 0);

    evdevInternal[index / 8] |= (clicked << (index % 8));
}

bool ctrled = false;

bool shifted = false;
bool capsLocked = false;

char handle_kb_event()
{
    uint8_t scan_code = io_in8(PORT_KB_DATA);
    kb_evdev_generate(scan_code);

    if (scan_code == 0xE0)
    {
        uint8_t extended_code = io_in8(PORT_KB_DATA);
        kb_evdev_generate(extended_code);
        switch (extended_code)
        {
        case 0x48:
            return KEY_BUTTON_UP;
        case 0x50:
            return KEY_BUTTON_DOWN;
        case 0x4b:
            return KEY_BUTTON_LEFT;
        case 0x4d:
            return KEY_BUTTON_RIGHT;
        default:
            return 0;
        }
    }

    // Shift checks
    if (shifted == 1 && scan_code & 0x80)
    {
        if ((scan_code & 0x7F) == 42) // & 0x7F clears the release
        {
            shifted = 0;
            return 0;
        }
    }

    if (ctrled == 1 && scan_code & 0x80)
    {
        if ((scan_code & 0x7F) == 0x1d) // & 0x7F clears the release
        {
            ctrled = false;
            return 0;
        }
    }

    if (scan_code < sizeof(character_table) && !(scan_code & 0x80))
    {
        char character = (shifted || capsLocked) ? shifted_character_table[scan_code] : character_table[scan_code];

        if (character != 0)
        { // Normal char
            return character;
        }

        switch (scan_code)
        {
        case SCANCODE_ENTER:
            return CHARACTER_ENTER;
            break;
        case SCANCODE_BACK:
            return CHARACTER_BACK;
            break;
        case SCANCODE_SHIFT:
            shifted = true;
            break;
        case 0x1d:
            ctrled = true;
            break;
        case SCANCODE_CAPS:
            capsLocked = !capsLocked;
            break;
        }
    }

    return 0;
}
