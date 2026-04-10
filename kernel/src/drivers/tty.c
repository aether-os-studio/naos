#include <drivers/tty.h>
#include <dev/device.h>
#include <mm/mm.h>
#include <boot/boot.h>
#include <task/task.h>
#include <task/signal.h>

DEFINE_LLIST(tty_device_list);
tty_t *kernel_session = NULL; // 内核会话

extern void send_process_group_signal(int pgid, int sig);

#define TTY_INPUT_BUF_SIZE 1024

static inline bool tty_bitmap_test(const uint8_t *bitmap, size_t bit) {
    return bitmap && (bitmap[bit / 8] & (1u << (bit % 8))) != 0;
}

static bool tty_input_enqueue_byte(tty_t *tty, char c) {
    if (!tty)
        return false;

    if (tty->input_count >= TTY_INPUT_BUF_SIZE) {
        tty->input_head = (tty->input_head + 1) % TTY_INPUT_BUF_SIZE;
        tty->input_count--;
    }

    tty->input_buf[tty->input_tail] = c;
    tty->input_tail = (tty->input_tail + 1) % TTY_INPUT_BUF_SIZE;
    tty->input_count++;
    return true;
}

static bool tty_input_dequeue_byte(tty_t *tty, char *c) {
    if (!tty || !c || tty->input_count == 0)
        return false;

    *c = tty->input_buf[tty->input_head];
    tty->input_head = (tty->input_head + 1) % TTY_INPUT_BUF_SIZE;
    tty->input_count--;
    return true;
}

static void tty_echo_bytes(tty_t *tty, const char *buf, size_t len) {
    if (!tty || !buf || len == 0 || !(tty->termios.c_lflag & ECHO))
        return;

    tty->ops.write(tty, buf, len);
}

static void tty_echo_erase(tty_t *tty) {
    static const char erase_seq[] = "\b \b";

    if (!tty || !(tty->termios.c_lflag & ECHO))
        return;

    if (tty->termios.c_lflag & ECHOE)
        tty->ops.write(tty, erase_seq, sizeof(erase_seq) - 1);
}

static void tty_input_commit_canon(tty_t *tty) {
    if (!tty)
        return;

    for (uint16_t i = 0; i < tty->canon_count; i++)
        tty_input_enqueue_byte(tty, tty->canon_buf[i]);
    tty->canon_count = 0;
}

static char tty_shifted_digit(uint16_t code) {
    switch (code) {
    case KEY_1:
        return '!';
    case KEY_2:
        return '@';
    case KEY_3:
        return '#';
    case KEY_4:
        return '$';
    case KEY_5:
        return '%';
    case KEY_6:
        return '^';
    case KEY_7:
        return '&';
    case KEY_8:
        return '*';
    case KEY_9:
        return '(';
    case KEY_0:
        return ')';
    default:
        return 0;
    }
}

typedef struct tty_keymap_entry {
    uint16_t code;
    char normal;
    char shifted;
} tty_keymap_entry_t;

static const tty_keymap_entry_t tty_keymap[] = {
    {KEY_1, '1', '!'},   {KEY_2, '2', '@'},   {KEY_3, '3', '#'},
    {KEY_4, '4', '$'},   {KEY_5, '5', '%'},   {KEY_6, '6', '^'},
    {KEY_7, '7', '&'},   {KEY_8, '8', '*'},   {KEY_9, '9', '('},
    {KEY_0, '0', ')'},   {KEY_A, 'a', 'A'},   {KEY_B, 'b', 'B'},
    {KEY_C, 'c', 'C'},   {KEY_D, 'd', 'D'},   {KEY_E, 'e', 'E'},
    {KEY_F, 'f', 'F'},   {KEY_G, 'g', 'G'},   {KEY_H, 'h', 'H'},
    {KEY_I, 'i', 'I'},   {KEY_J, 'j', 'J'},   {KEY_K, 'k', 'K'},
    {KEY_L, 'l', 'L'},   {KEY_M, 'm', 'M'},   {KEY_N, 'n', 'N'},
    {KEY_O, 'o', 'O'},   {KEY_P, 'p', 'P'},   {KEY_Q, 'q', 'Q'},
    {KEY_R, 'r', 'R'},   {KEY_S, 's', 'S'},   {KEY_T, 't', 'T'},
    {KEY_U, 'u', 'U'},   {KEY_V, 'v', 'V'},   {KEY_W, 'w', 'W'},
    {KEY_X, 'x', 'X'},   {KEY_Y, 'y', 'Y'},   {KEY_Z, 'z', 'Z'},
    {KEY_KP0, '0', '0'}, {KEY_KP1, '1', '1'}, {KEY_KP2, '2', '2'},
    {KEY_KP3, '3', '3'}, {KEY_KP4, '4', '4'}, {KEY_KP5, '5', '5'},
    {KEY_KP6, '6', '6'}, {KEY_KP7, '7', '7'}, {KEY_KP8, '8', '8'},
    {KEY_KP9, '9', '9'},
};

static bool tty_lookup_key_char(uint16_t code, bool shift, bool caps,
                                char *ch) {
    if (!ch)
        return false;

    for (size_t i = 0; i < sizeof(tty_keymap) / sizeof(tty_keymap[0]); i++) {
        if (tty_keymap[i].code != code)
            continue;

        *ch = shift ? tty_keymap[i].shifted : tty_keymap[i].normal;
        if (tty_keymap[i].normal >= 'a' && tty_keymap[i].normal <= 'z' &&
            (shift ^ caps))
            *ch = tty_keymap[i].shifted;
        else if (tty_keymap[i].normal >= 'a' && tty_keymap[i].normal <= 'z' &&
                 !(shift ^ caps))
            *ch = tty_keymap[i].normal;
        return true;
    }

    return false;
}

static bool tty_translate_key(tty_t *tty, uint16_t code, char *out,
                              size_t *out_len) {
    bool shift;
    bool ctrl;
    bool caps;
    char ch = 0;
    const char *seq = NULL;
    size_t len = 0;

    if (!tty || !out || !out_len)
        return false;

    shift = tty->key_shift;
    ctrl = tty->key_ctrl;
    caps = tty->key_capslock;

    switch (code) {
    case KEY_ENTER:
    case KEY_KPENTER:
        ch = '\n';
        break;
    case KEY_ESC:
        ch = 27;
        break;
    case KEY_BACKSPACE:
        ch = 127;
        break;
    case KEY_TAB:
        ch = '\t';
        break;
    case KEY_SPACE:
        ch = ' ';
        break;
    case KEY_MINUS:
        ch = shift ? '_' : '-';
        break;
    case KEY_EQUAL:
    case KEY_KPEQUAL:
        ch = shift ? '+' : '=';
        break;
    case KEY_LEFTBRACE:
        ch = shift ? '{' : '[';
        break;
    case KEY_RIGHTBRACE:
        ch = shift ? '}' : ']';
        break;
    case KEY_BACKSLASH:
        ch = shift ? '|' : '\\';
        break;
    case KEY_SEMICOLON:
        ch = shift ? ':' : ';';
        break;
    case KEY_APOSTROPHE:
        ch = shift ? '"' : '\'';
        break;
    case KEY_GRAVE:
        ch = shift ? '~' : '`';
        break;
    case KEY_COMMA:
        ch = shift ? '<' : ',';
        break;
    case KEY_DOT:
        ch = shift ? '>' : '.';
        break;
    case KEY_SLASH:
    case KEY_KPSLASH:
        ch = shift ? '?' : '/';
        break;
    case KEY_KPASTERISK:
        ch = '*';
        break;
    case KEY_KPMINUS:
        ch = '-';
        break;
    case KEY_KPPLUS:
        ch = '+';
        break;
    case KEY_KPDOT:
        ch = '.';
        break;
    case KEY_UP:
        seq = "\033[A";
        break;
    case KEY_DOWN:
        seq = "\033[B";
        break;
    case KEY_RIGHT:
        seq = "\033[C";
        break;
    case KEY_LEFT:
        seq = "\033[D";
        break;
    case KEY_HOME:
        seq = "\033[H";
        break;
    case KEY_END:
        seq = "\033[F";
        break;
    case KEY_PAGEUP:
        seq = "\033[5~";
        break;
    case KEY_PAGEDOWN:
        seq = "\033[6~";
        break;
    case KEY_INSERT:
        seq = "\033[2~";
        break;
    case KEY_DELETE:
        seq = "\033[3~";
        break;
    default:
        break;
    }

    if (!ch && !seq)
        (void)tty_lookup_key_char(code, shift, caps, &ch);

    if (ctrl && ch >= 'a' && ch <= 'z')
        ch = (char)(ch - 'a' + 1);
    else if (ctrl && ch >= 'A' && ch <= 'Z')
        ch = (char)(ch - 'A' + 1);

    if (seq) {
        len = strlen(seq);
        memcpy(out, seq, len);
        *out_len = len;
        return true;
    }

    if (!ch)
        return false;

    out[0] = ch;
    *out_len = 1;
    return true;
}

static void tty_receive_bytes(tty_t *tty, const char *buf, size_t len) {
    bool canonical;
    char eofc;

    if (!tty || !buf || len == 0)
        return;

    canonical = (tty->termios.c_lflag & ICANON) != 0;
    eofc = tty->termios.c_cc[VEOF];

    for (size_t i = 0; i < len; i++) {
        char c = buf[i];

        if ((tty->termios.c_iflag & IGNCR) && c == '\r')
            continue;
        if ((tty->termios.c_iflag & ICRNL) && c == '\r')
            c = '\n';
        else if ((tty->termios.c_iflag & INLCR) && c == '\n')
            c = '\r';

        if (tty->termios.c_lflag & ISIG) {
            uint64_t pgid = tty->at_process_group_id;
            if (pgid) {
                if (c == tty->termios.c_cc[VINTR]) {
                    send_process_group_signal(pgid, SIGINT);
                    continue;
                }
                if (c == tty->termios.c_cc[VQUIT]) {
                    send_process_group_signal(pgid, SIGQUIT);
                    continue;
                }
                if (c == tty->termios.c_cc[VSUSP]) {
                    send_process_group_signal(pgid, SIGTSTP);
                    continue;
                }
            }
        }

        if (!canonical) {
            tty_input_enqueue_byte(tty, c);
            tty_echo_bytes(tty, &c, 1);
            continue;
        }

        if (c == tty->termios.c_cc[VERASE] || c == 127) {
            if (tty->canon_count > 0) {
                tty->canon_count--;
                tty_echo_erase(tty);
            }
            continue;
        }

        if (c == tty->termios.c_cc[VKILL]) {
            while (tty->canon_count > 0) {
                tty->canon_count--;
                tty_echo_erase(tty);
            }
            if (tty->termios.c_lflag & ECHOK)
                tty_echo_bytes(tty, "\n", 1);
            continue;
        }

        if (c == eofc) {
            tty_input_commit_canon(tty);
            continue;
        }

        if (tty->canon_count < TTY_INPUT_BUF_SIZE)
            tty->canon_buf[tty->canon_count++] = c;
        tty_echo_bytes(tty, &c, 1);

        if (c == '\n' || c == tty->termios.c_cc[VEOL]) {
            tty_input_commit_canon(tty);
        }
    }
}

static bool tty_input_device_is_keyboard(dev_input_event_t *event) {
    if (!event)
        return false;

    return tty_bitmap_test(event->evbit, EV_KEY) &&
           (tty_bitmap_test(event->keybit, KEY_A) ||
            tty_bitmap_test(event->keybit, KEY_ENTER) ||
            tty_bitmap_test(event->keybit, KEY_SPACE));
}

size_t tty_input_read(tty_t *tty, char *buf, size_t count) {
    size_t read = 0;
    int vmin;

    if (!tty || !buf || count == 0)
        return 0;

    vmin = tty->termios.c_cc[VMIN];
    if (vmin <= 0)
        vmin = 1;

    while (read < count) {
        arch_enable_interrupt();

        if (task_signal_has_deliverable(current_task)) {
            arch_disable_interrupt();
            return read ? read : (size_t)-EINTR;
        }

        if (tty_input_dequeue_byte(tty, &buf[read])) {
            read++;
            if (!(tty->termios.c_lflag & ICANON) && read >= (size_t)vmin)
                break;
            if ((tty->termios.c_lflag & ICANON) && buf[read - 1] == '\n')
                break;
            continue;
        }

        if (read > 0)
            break;

        schedule(SCHED_FLAG_YIELD);
    }

    arch_disable_interrupt();
    return read;
}

int tty_input_poll(tty_t *tty, int events) {
    ssize_t revents = 0;

    if (!tty)
        return 0;

    if ((events & EPOLLIN) && tty->input_count > 0)
        revents |= EPOLLIN;
    if (events & EPOLLOUT)
        revents |= EPOLLOUT;

    return revents;
}

void tty_input_flush(tty_t *tty) {
    if (!tty)
        return;

    tty->input_head = 0;
    tty->input_tail = 0;
    tty->input_count = 0;
    tty->canon_count = 0;
}

void tty_input_event(dev_input_event_t *event, uint16_t type, uint16_t code,
                     int32_t value) {
    tty_t *tty = kernel_session;
    char out[8];
    size_t out_len = 0;

    if (!tty || !tty_input_device_is_keyboard(event) || type != EV_KEY)
        return;

    switch (code) {
    case KEY_LEFTSHIFT:
    case KEY_RIGHTSHIFT:
        tty->key_shift = value != 0;
        return;
    case KEY_LEFTCTRL:
    case KEY_RIGHTCTRL:
        tty->key_ctrl = value != 0;
        return;
    case KEY_LEFTALT:
    case KEY_RIGHTALT:
        tty->key_alt = value != 0;
        return;
    case KEY_CAPSLOCK:
        if (value == 1)
            tty->key_capslock = !tty->key_capslock;
        return;
    default:
        break;
    }

    if (value == 0)
        return;

    if (!tty_translate_key(tty, code, out, &out_len))
        return;

    tty_receive_bytes(tty, out, out_len);
}

tty_device_t *alloc_tty_device(enum tty_device_type type) {
    tty_device_t *device = (tty_device_t *)calloc(1, sizeof(tty_device_t));
    device->type = type;
    llist_init_head(&device->node);
    return device;
}

uint64_t register_tty_device(tty_device_t *device) {
    if (device->private_data == NULL)
        return -EINVAL;
    llist_append(&tty_device_list, &device->node);
    return EOK;
}

uint64_t delete_tty_device(tty_device_t *device) {
    if (device == NULL)
        return -EINVAL;
    free(device->private_data);
    llist_delete(&device->node);
    free(device);
    return EOK;
}

tty_device_t *get_tty_device(const char *name) {
    if (name == NULL)
        return NULL;
    tty_device_t *pos = NULL;
    tty_device_t *n = NULL;
    llist_for_each(pos, n, &tty_device_list, node) {
        if (strcmp(pos->name, name) == 0) {
            return pos;
        }
    }
    return NULL;
}

char *default_console = NULL;

void parse_cmdline_console(const char *cmdline) {
    static char console_name[64];
    memset(console_name, 0, sizeof(console_name));

    boot_framebuffer_t *boot_fb = boot_get_framebuffer();
    if (!boot_fb) {
        strncpy(console_name, "ttyS0", sizeof(console_name));
        goto next;
    }

    if (!cmdline || !*cmdline) {
        strcpy(console_name, DEFAULT_TTY);
        goto next;
    }

    const char *key = "console=";
    const char *pos = strstr(cmdline, key);
    if (!pos) {
        strcpy(console_name, DEFAULT_TTY);
        goto next;
    }

    pos += strlen(key);

    size_t i = 0;
    while (*pos && *pos != ' ' && i < sizeof(console_name) - 1) {
        console_name[i++] = *pos++;
    }
    console_name[i] = '\0';

next:
    char buf[64];
    sprintf(buf, "/dev/%s", console_name);

    default_console = strdup(buf);
}

void tty_init() {
    kernel_session = malloc(sizeof(tty_t));

    boot_framebuffer_t *framebuffer = boot_get_framebuffer();

    if (framebuffer) {
        tty_device_t *fb_device = alloc_tty_device(TTY_DEVICE_GRAPHI);
        struct tty_graphics_ *graphics = malloc(sizeof(struct tty_graphics_));

        graphics->address = (void *)framebuffer->address;
        graphics->width = framebuffer->width;
        graphics->height = framebuffer->height;
        graphics->bpp = framebuffer->bpp;
        graphics->pitch = framebuffer->pitch;

        graphics->blue_mask_shift = framebuffer->blue_mask_shift;
        graphics->red_mask_shift = framebuffer->red_mask_shift;
        graphics->green_mask_shift = framebuffer->green_mask_shift;
        graphics->blue_mask_size = framebuffer->blue_mask_size;
        graphics->red_mask_size = framebuffer->red_mask_size;
        graphics->green_mask_size = framebuffer->green_mask_size;

        fb_device->private_data = graphics;

        char name[32];
        sprintf(name, "tty%lu", 0);
        strcpy(fb_device->name, name);
        register_tty_device(fb_device);
    }

    tty_device_t *serial_dev = alloc_tty_device(TTY_DEVICE_SERIAL);
    struct tty_serial_ *serial = malloc(sizeof(struct tty_serial_));
    serial->port = 0;

    serial_dev->private_data = serial;
    strcpy(serial_dev->name, "ttyS0");
    register_tty_device(serial_dev);

    // 解析命令行 console 参数
    const char *cmdline = boot_get_cmdline();
    parse_cmdline_console(cmdline);

    if (!strncmp(default_console, "/dev/ttyS", 9)) {
        tty_init_session_serial();
    } else {
        tty_init_session();
    }
}

extern void create_session_terminal(tty_t *tty);
extern void create_session_terminal_serial(tty_t *tty);

int tty_ioctl(void *dev, int cmd, void *args) {
    tty_t *tty = dev;
    return tty->ops.ioctl(tty, cmd, (uint64_t)args);
}

int tty_poll(void *dev, int events) {
    tty_t *tty = dev;
    return tty->ops.poll(tty, events);
}

int tty_read(void *dev, void *buf, uint64_t offset, size_t size,
             uint64_t flags) {
    tty_t *tty = dev;
    return tty->ops.read(tty, buf, size);
}

int tty_write(void *dev, const void *buf, uint64_t offset, size_t size,
              uint64_t flags) {
    tty_t *tty = dev;
    return tty->ops.write(tty, buf, size);
}

void tty_init_session() {
    const char *tty_name = "tty0";
    tty_device_t *device = get_tty_device(tty_name);
    if (!device) {
        printk("tty_init_session: no device '%s', fallback to last tty\n",
               tty_name);
        device = container_of(tty_device_list.prev, tty_device_t, node);
    }

    tty_t *tty = calloc(1, sizeof(tty_t));
    tty->device = device;
    create_session_terminal(tty);
    device_install(DEV_CHAR, DEV_TTY, tty, tty_name, 0, NULL, NULL, tty_ioctl,
                   tty_poll, tty_read, tty_write, NULL);

    kernel_session = tty;
}

void tty_init_session_serial() {
    const char *tty_name = "ttyS0";
    tty_device_t *device = get_tty_device(tty_name);
    if (!device) {
        printk("tty_init_serial: device not found: %s\n", tty_name);
        return;
    }

    tty_t *tty = calloc(1, sizeof(tty_t));
    tty->device = device;
    create_session_terminal_serial(tty);
    device_install(DEV_CHAR, DEV_TTY, tty, tty_name, 0, NULL, NULL, tty_ioctl,
                   tty_poll, tty_read, tty_write, NULL);

    kernel_session = tty;
}
