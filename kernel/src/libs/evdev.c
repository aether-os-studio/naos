#include <libs/klibc.h>
#include <libs/keys.h>
#include <fs/vfs/dev.h>
#include <fs/fs_syscall.h>
#include <drivers/tty.h>

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

#define KB_QUEUE_SIZE 256

typedef struct {
    char buffer[KB_QUEUE_SIZE];
    uint16_t head;
    uint16_t tail;
    uint16_t count;
} kb_queue_t;

static kb_queue_t kb_queue = {{0}, 0, 0, 0};

// 修饰键状态
static struct {
    bool shift;
    bool ctrl;
    bool alt;
    bool caps_lock;
} kb_mods = {0, 0, 0, 0};

static const char scancode_map[] = {
    0,    0,   '1', '2',  '3',  '4', '5',  '6',  // 0x00-0x07
    '7',  '8', '9', '0',  '-',  '=', '\b', '\t', // 0x08-0x0F
    'q',  'w', 'e', 'r',  't',  'y', 'u',  'i',  // 0x10-0x17
    'o',  'p', '[', ']',  '\n', 0,   'a',  's',  // 0x18-0x1F
    'd',  'f', 'g', 'h',  'j',  'k', 'l',  ';',  // 0x20-0x27
    '\'', '`', 0,   '\\', 'z',  'x', 'c',  'v',  // 0x28-0x2F
    'b',  'n', 'm', ',',  '.',  '/', 0,    '*',  // 0x30-0x37
    0,    ' ', 0                                 // 0x38-0x3A
};

static const char scancode_map_shift[] = {
    0,   0,   '!', '@', '#',  '$', '%',  '^',  // 0x00-0x07
    '&', '*', '(', ')', '_',  '+', '\b', '\t', // 0x08-0x0F
    'Q', 'W', 'E', 'R', 'T',  'Y', 'U',  'I',  // 0x10-0x17
    'O', 'P', '{', '}', '\n', 0,   'A',  'S',  // 0x18-0x1F
    'D', 'F', 'G', 'H', 'J',  'K', 'L',  ':',  // 0x20-0x27
    '"', '~', 0,   '|', 'Z',  'X', 'C',  'V',  // 0x28-0x2F
    'B', 'N', 'M', '<', '>',  '?', 0,    '*',  // 0x30-0x37
    0,   ' ', 0                                // 0x38-0x3A
};

static bool queue_push(char c) {
    if (kb_queue.count >= KB_QUEUE_SIZE) {
        return false;
    }
    kb_queue.buffer[kb_queue.tail] = c;
    kb_queue.tail = (kb_queue.tail + 1) % KB_QUEUE_SIZE;
    kb_queue.count++;
    return true;
}

static bool queue_pop(char *c) {
    if (kb_queue.count == 0) {
        return false;
    }
    *c = kb_queue.buffer[kb_queue.head];
    kb_queue.head = (kb_queue.head + 1) % KB_QUEUE_SIZE;
    kb_queue.count--;
    return true;
}

static void queue_push_string(const char *str) {
    while (*str) {
        if (!queue_push(*str++)) {
            break;
        }
    }
}

// ============ 特殊键处理 ============
static const char *get_escape_sequence(uint8_t sc) {
    switch (sc) {
    case 0x48:
        return "\x1b[A"; // ↑
    case 0x50:
        return "\x1b[B"; // ↓
    case 0x4D:
        return "\x1b[C"; // →
    case 0x4B:
        return "\x1b[D"; // ←
    case 0x47:
        return "\x1b[H"; // Home
    case 0x4F:
        return "\x1b[F"; // End
    case 0x49:
        return "\x1b[5~"; // PgUp
    case 0x51:
        return "\x1b[6~"; // PgDn
    case 0x52:
        return "\x1b[2~"; // Insert
    case 0x53:
        return "\x1b[3~"; // Delete
    case 0x3B:
        return "\x1bOP"; // F1
    case 0x3C:
        return "\x1bOQ"; // F2
    case 0x3D:
        return "\x1bOR"; // F3
    case 0x3E:
        return "\x1bOS"; // F4
    case 0x3F:
        return "\x1b[15~"; // F5
    case 0x40:
        return "\x1b[17~"; // F6
    case 0x41:
        return "\x1b[18~"; // F7
    case 0x42:
        return "\x1b[19~"; // F8
    case 0x43:
        return "\x1b[20~"; // F9
    case 0x44:
        return "\x1b[21~"; // F10
    case 0x57:
        return "\x1b[23~"; // F11
    case 0x58:
        return "\x1b[24~"; // F12
    default:
        return NULL;
    }
}

extern tty_t *kernel_session;

void handle_kb_event(uint8_t scan_code, bool pressed) {
    kb_evdev_generate(scan_code, pressed);

    if (!pressed) {
        switch (scan_code) {
        case 0x2A:
        case 0x36:
            kb_mods.shift = false;
            break;
        case 0x1D:
            kb_mods.ctrl = false;
            break;
        case 0x38:
            kb_mods.alt = false;
            break;
        }
        return;
    }

    switch (scan_code) {
    case 0x2A:
    case 0x36:
        kb_mods.shift = true;
        return;
    case 0x1D:
        kb_mods.ctrl = true;
        return;
    case 0x38:
        kb_mods.alt = true;
        return;
    case 0x3A:
        kb_mods.caps_lock = !kb_mods.caps_lock;
        return;
    }

    const char *esc_seq = get_escape_sequence(scan_code);
    if (esc_seq) {
        if (kernel_session && kernel_session->termios.c_lflag & ECHO) {
            printk("%s", esc_seq);
        }
        queue_push_string(esc_seq);

        return;
    }

    if (scan_code >= sizeof(scancode_map)) {
        return;
    }

    char c =
        kb_mods.shift ? scancode_map_shift[scan_code] : scancode_map[scan_code];

    if (c == 0)
        return;

    if (kb_mods.caps_lock) {
        if (c >= 'a' && c <= 'z') {
            c = c - 'a' + 'A';
        } else if (kb_mods.shift && c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }
    }

    if (kb_mods.ctrl) {
        if (c >= 'a' && c <= 'z') {
            c = c - 'a' + 1;
        } else if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 1;
        }
    }

    if (kernel_session && kernel_session->termios.c_lflag & ECHO) {
        printk("%c", c);
    }
    queue_push(c);
}

int kb_read(char *buffer, int n) {
    int i;
    for (i = 0; i < n; i++) {
        if (!queue_pop(&buffer[i])) {
            break;
        }
    }
    return i;
}

int kb_available() { return kb_queue.count; }

void kb_clear() {
    kb_queue.head = 0;
    kb_queue.tail = 0;
    kb_queue.count = 0;
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
