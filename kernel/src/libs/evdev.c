#include <libs/klibc.h>
#include <libs/keys.h>
#include <fs/vfs/dev.h>
#include <fs/fs_syscall.h>
#include <drivers/tty.h>

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

void kb_evdev_generate(uint8_t code, bool clicked) {
    if (!kb_input_event || !kb_input_event->timesOpened)
        return;

    struct timespec now;
    sys_clock_gettime(kb_input_event->clock_id, (uint64_t)&now, 0);

    input_generate_event(kb_input_event, EV_KEY, code, clicked ? 1 : 0,
                         now.tv_sec, now.tv_nsec / 1000);
    input_generate_event(kb_input_event, EV_SYN, SYN_REPORT, 0, now.tv_sec,
                         now.tv_nsec / 1000);
}

#define KB_QUEUE_SIZE 256

typedef struct {
    char tmp_buffer[KB_QUEUE_SIZE];
    uint16_t tmp_head;
    uint16_t tmp_tail;
    uint16_t tmp_count;
    char buffer[KB_QUEUE_SIZE];
    uint16_t head;
    uint16_t tail;
    uint16_t count;
} kb_queue_t;

static kb_queue_t kb_queue = {{0}, 0, 0, 0, {0}, 0, 0, 0};

// 修饰键状态
static struct {
    bool shift;
    bool ctrl;
    bool alt;
    bool caps_lock;
} kb_mods = {0, 0, 0, 0};

char scancode_map[140] = {
    0,   0,    '1',  '2', '3',  '4', '5', '6', '7', '8', '9', '0', '-',
    '=', '\b', '\t', 'q', 'w',  'e', 'r', 't', 'y', 'u', 'i', 'o', 'p',
    '[', ']',  '\n', 0,   'a',  's', 'd', 'f', 'g', 'h', 'j', 'k', 'l',
    ';', '\'', '`',  0,   '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',',
    '.', '/',  0,    '*', 0,    ' ', 0,   0,   0,   0,   0,   0,   0,
    0,   0,    0,    0,   0,    0,   '7', '8', '9', '-', '4', '5', '6',
    '+', '1',  '2',  '3', '0',  '.', 0,   0,   0,   0,   0};

char scancode_map_shift[140] = {
    0,   0,    '!',  '@', '#', '$', '%', '^', '&', '*', '(', ')', '_',
    '+', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P',
    '{', '}',  '\n', 0,   'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L',
    ':', '\"', '~',  0,   '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<',
    '>', '?',  0,    '*', 0,   ' ', 0,   0,   0,   0,   0,   0,   0,
    0,   0,    0,    0,   0,   0,   '7', '8', '9', '-', '4', '5', '6',
    '+', '1',  '2',  '3', '0', '.', 0,   0,   0,   0,   0};

static bool queue_push(char c) {
    if (kb_queue.tmp_count >= KB_QUEUE_SIZE) {
        return false;
    }
    kb_queue.tmp_buffer[kb_queue.tmp_tail] = c;
    kb_queue.tmp_tail = (kb_queue.tmp_tail + 1) % KB_QUEUE_SIZE;
    kb_queue.tmp_count++;
    return true;
}

static bool queue_pop_tmp(char *c) {
    if (kb_queue.tmp_count == 0) {
        return false;
    }
    *c = kb_queue.tmp_buffer[kb_queue.tmp_head];
    kb_queue.tmp_head = (kb_queue.tmp_head + 1) % KB_QUEUE_SIZE;
    kb_queue.tmp_count--;
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

static bool queue_flush() {
    if (kb_queue.tmp_count == 0) {
        return false;
    }

    int i = 0;
    while (kb_queue.tmp_count > 0) {
        queue_pop_tmp(&kb_queue.buffer[kb_queue.tail]);
        kb_queue.tail = (kb_queue.tail + 1) % KB_QUEUE_SIZE;
        if (kb_queue.count < KB_QUEUE_SIZE) {
            kb_queue.count++;
        } else {
            kb_queue.head = (kb_queue.head + 1) % KB_QUEUE_SIZE;
        }
        i++;
    }

    (void)i;

    return true;
}

static void queue_push_string(const char *str) {
    while (*str) {
        if (!queue_push(*str++)) {
            break;
        }
    }
    queue_flush();
}

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
}

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

void handle_kb_scancode(uint8_t scan_code, bool pressed) {
    if ((scan_code < (sizeof(evdevTable) / sizeof(evdevTable[0]))) &&
        evdevTable[scan_code])
        handle_kb_event(evdevTable[scan_code], pressed);

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

    if (kernel_session && (kernel_session->termios.c_lflag & ECHO)) {
        printk("%c", c);
    }
    queue_push(c);

    queue_flush();
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
