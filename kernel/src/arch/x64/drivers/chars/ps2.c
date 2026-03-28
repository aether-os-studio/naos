#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <libs/keys.h>
#include <init/abis.h>
#include <boot/boot.h>
#include <fs/vfs/vfs.h>
#include <linuxabi.h>

static struct {
    ps2_keyboard_callback_t keyboard_callback;
    ps2_mouse_callback_t mouse_callback;

    // 键盘状态
    bool keyboard_extended;

    // 鼠标状态
    uint8_t mouse_cycle;
    uint8_t mouse_packet[4];
    bool mouse_has_wheel;
    bool mouse_left_pressed;
    bool mouse_right_pressed;
    bool mouse_middle_pressed;

    bool port1_available;
    bool port2_available;
} ps2_state = {0};

static bool ps2_input_now(dev_input_event_t *event, struct timespec *now) {
    if (!event || !now)
        return false;

    uint64_t nano = nano_time();
    if (event->clock_id == CLOCK_REALTIME)
        now->tv_sec = boot_get_boottime() + nano / 1000000000;
    else
        now->tv_sec = nano / 1000000000;
    now->tv_nsec = nano % 1000000000;
    return true;
}

// 等待可以写入
static bool ps2_wait_write(void) {
    uint64_t deadline = nano_time() + 1000ULL * 1000000ULL;
    while (nano_time() < deadline) {
        if ((io_in8(PS2_STATUS_PORT) & 0x02) == 0) {
            return true;
        }
    }
    return false;
}

// 等待可以读取
static bool ps2_wait_read(void) {
    uint64_t deadline = nano_time() + 1000ULL * 1000000ULL;
    while (nano_time() < deadline) {
        if (io_in8(PS2_STATUS_PORT) & 0x01) {
            return true;
        }
    }
    return false;
}

// 读取数据
static uint8_t ps2_read_data(void) {
    if (!ps2_wait_read()) {
        return 0xFF;
    }
    return io_in8(PS2_DATA_PORT);
}

// 写入命令
static void ps2_write_command(uint8_t cmd) {
    if (!ps2_wait_write()) {
        return;
    }
    io_out8(PS2_COMMAND_PORT, cmd);
}

// 写入数据
static void ps2_write_data(uint8_t data) {
    if (!ps2_wait_write()) {
        return;
    }
    io_out8(PS2_DATA_PORT, data);
}

// 发送命令到第一个端口（键盘）
static bool ps2_send_to_port1(uint8_t cmd) {
    for (int i = 0; i < 3; i++) {
        ps2_write_data(cmd);
        uint8_t response = ps2_read_data();
        if (response == PS2_ACK) {
            return true;
        }
        if (response != PS2_RESEND) {
            break;
        }
    }
    return false;
}

// 发送命令到第二个端口（鼠标）
static bool ps2_send_to_port2(uint8_t cmd) {
    for (int i = 0; i < 3; i++) {
        ps2_write_command(PS2_CMD_WRITE_PORT2);
        ps2_write_data(cmd);
        uint8_t response = ps2_read_data();
        if (response == PS2_ACK) {
            return true;
        }
        if (response != PS2_RESEND) {
            break;
        }
    }
    return false;
}

// 设置鼠标采样率（用于检测滚轮）
static bool ps2_mouse_set_sample_rate(uint8_t rate) {
    if (!ps2_send_to_port2(PS2_DEV_SET_SAMPLE_RATE)) {
        return false;
    }
    if (!ps2_send_to_port2(rate)) {
        return false;
    }
    return true;
}

// 检测并启用鼠标滚轮
static bool ps2_mouse_detect_wheel(void) {
    // 使用魔术序列：200, 100, 80 来启用Intellimouse模式
    if (!ps2_mouse_set_sample_rate(200))
        return false;
    if (!ps2_mouse_set_sample_rate(100))
        return false;
    if (!ps2_mouse_set_sample_rate(80))
        return false;

    // 读取设备ID
    if (!ps2_send_to_port2(PS2_DEV_IDENTIFY)) {
        return false;
    }

    uint8_t id = ps2_read_data();

    // ID = 3 表示支持滚轮
    // ID = 4 表示支持滚轮和5个按钮
    return (id == 3 || id == 4);
}

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

dev_input_event_t *ps2_kb_input_event = NULL;
dev_input_event_t *ps2_mouse_input_event = NULL;

void ps2_keyboard_callback(ps2_keyboard_event_t event) {
    if (!system_abi || !system_abi->input_generate_event || !ps2_kb_input_event)
        return;

    struct timespec now;
    if (!ps2_input_now(ps2_kb_input_event, &now))
        return;

    uint16_t code =
        evdev_code_from_set1_scancode(event.scancode, event.is_extended);
    if (!code)
        return;

    system_abi->input_generate_event(ps2_kb_input_event, EV_KEY, code,
                                     event.pressed ? 1 : 0, now.tv_sec,
                                     now.tv_nsec / 1000);
    system_abi->input_generate_event(ps2_kb_input_event, EV_SYN, SYN_REPORT, 0,
                                     now.tv_sec, now.tv_nsec / 1000);
}

void ps2_mouse_callback(ps2_mouse_event_t event) {
    if (!system_abi || !system_abi->input_generate_event ||
        !ps2_mouse_input_event)
        return;

    struct timespec now;
    if (!ps2_input_now(ps2_mouse_input_event, &now))
        return;

    bool emitted = false;

    if (event.x) {
        system_abi->input_generate_event(ps2_mouse_input_event, EV_REL, REL_X,
                                         event.x, now.tv_sec,
                                         now.tv_nsec / 1000);
        emitted = true;
    }
    if (event.y) {
        system_abi->input_generate_event(ps2_mouse_input_event, EV_REL, REL_Y,
                                         event.y, now.tv_sec,
                                         now.tv_nsec / 1000);
        emitted = true;
    }
    if (event.z) {
        system_abi->input_generate_event(ps2_mouse_input_event, EV_REL,
                                         REL_WHEEL, -event.z, now.tv_sec,
                                         now.tv_nsec / 1000);
        emitted = true;
    }

    if (ps2_state.mouse_left_pressed != event.left_button) {
        ps2_state.mouse_left_pressed = event.left_button;
        system_abi->input_generate_event(ps2_mouse_input_event, EV_KEY,
                                         BTN_LEFT, event.left_button ? 1 : 0,
                                         now.tv_sec, now.tv_nsec / 1000);
        emitted = true;
    }
    if (ps2_state.mouse_right_pressed != event.right_button) {
        ps2_state.mouse_right_pressed = event.right_button;
        system_abi->input_generate_event(ps2_mouse_input_event, EV_KEY,
                                         BTN_RIGHT, event.right_button ? 1 : 0,
                                         now.tv_sec, now.tv_nsec / 1000);
        emitted = true;
    }
    if (ps2_state.mouse_middle_pressed != event.middle_button) {
        ps2_state.mouse_middle_pressed = event.middle_button;
        system_abi->input_generate_event(
            ps2_mouse_input_event, EV_KEY, BTN_MIDDLE,
            event.middle_button ? 1 : 0, now.tv_sec, now.tv_nsec / 1000);
        emitted = true;
    }

    if (emitted) {
        system_abi->input_generate_event(ps2_mouse_input_event, EV_SYN,
                                         SYN_REPORT, 0, now.tv_sec,
                                         now.tv_nsec / 1000);
    }
}

// 初始化PS/2控制器
bool ps2_init(void) {
    // 1. 禁用设备
    ps2_write_command(PS2_CMD_DISABLE_PORT1);
    ps2_write_command(PS2_CMD_DISABLE_PORT2);

    // 2. 清空输出缓冲区
    io_in8(PS2_DATA_PORT);

    // 3. 设置控制器配置
    ps2_write_command(PS2_CMD_READ_CONFIG);
    uint8_t config = ps2_read_data();

    // 禁用中断和翻译
    config &= ~0x43;

    // 检查是否是双通道
    bool is_dual_channel = (config & 0x20) != 0;

    ps2_write_command(PS2_CMD_WRITE_CONFIG);
    ps2_write_data(config);

    // 4. 执行控制器自检
    ps2_write_command(PS2_CMD_TEST_CONTROLLER);
    if (ps2_read_data() != 0x55) {
        return false;
    }

    // 5. 确定可用端口数量
    if (is_dual_channel) {
        ps2_write_command(PS2_CMD_ENABLE_PORT2);
        ps2_write_command(PS2_CMD_READ_CONFIG);
        config = ps2_read_data();
        if ((config & 0x20) == 0) {
            ps2_state.port2_available = true;
            ps2_write_command(PS2_CMD_DISABLE_PORT2);
        }
    }

    // 6. 测试端口
    ps2_write_command(PS2_CMD_TEST_PORT1);
    if (ps2_read_data() == 0x00) {
        ps2_state.port1_available = true;
    }

    if (ps2_state.port2_available) {
        ps2_write_command(PS2_CMD_TEST_PORT2);
        if (ps2_read_data() != 0x00) {
            ps2_state.port2_available = false;
        }
    }

    return ps2_state.port1_available || ps2_state.port2_available;
}

// 初始化键盘
bool ps2_keyboard_init(void) {
    if (!ps2_state.port1_available) {
        return false;
    }

    // 启用端口1
    ps2_write_command(PS2_CMD_ENABLE_PORT1);

    // 重置键盘
    if (!ps2_send_to_port1(PS2_DEV_RESET)) {
        return false;
    }

    // 等待自检完成 (0xAA = 通过)
    if (ps2_read_data() != 0xAA) {
        return false;
    }

    // 启用扫描
    if (!ps2_send_to_port1(PS2_DEV_ENABLE)) {
        return false;
    }

    // 设置扫描码
    if (!ps2_send_to_port1(0xF0)) {
        return false;
    }

    if (!ps2_send_to_port1(0x01)) {
        return false;
    }

    // 启用中断
    ps2_write_command(PS2_CMD_READ_CONFIG);
    uint8_t config = ps2_read_data();
    config |= 0x01; // 启用端口1中断
    ps2_write_command(PS2_CMD_WRITE_CONFIG);
    ps2_write_data(config);

    ps2_keyboard_set_callback(ps2_keyboard_callback);

    regist_input_dev_arg_t arg = {0};
    arg.uevent_append = "ID_INPUT_KEYBOARD=1";
    arg.from = INPUT_FROM_PS2;
    input_dev_desc_set_event(&arg, EV_REP);
    for (int i = KEY_ESC; i <= KEY_MENU; i++)
        input_dev_desc_set_key(&arg, i);
    ps2_kb_input_event = system_abi->regist_input_dev("ps2kbd", &arg);

    irq_regist_irq(
        PS2_KBD_INTERRUPT_VECTOR,
        (void (*)(uint64_t, void *, struct pt_regs *))ps2_interrupt_handler, 1,
        NULL, &apic_controller, "PS/2 Keyboard", 0);

    return true;
}

// 初始化鼠标
bool ps2_mouse_init(void) {
    if (!ps2_state.port2_available) {
        return false;
    }

    // 启用端口2
    ps2_write_command(PS2_CMD_ENABLE_PORT2);

    // 重置鼠标
    if (!ps2_send_to_port2(PS2_DEV_RESET)) {
        return false;
    }

    // 等待自检完成
    if (ps2_read_data() != 0xAA) {
        return false;
    }

    // 读取设备ID (应该是 0x00)
    ps2_read_data();

    // 检测滚轮支持
    ps2_state.mouse_has_wheel = ps2_mouse_detect_wheel();

    // 设置默认值
    if (!ps2_send_to_port2(PS2_DEV_SET_DEFAULTS)) {
        return false;
    }

    // 启用数据报告
    if (!ps2_send_to_port2(PS2_DEV_ENABLE)) {
        return false;
    }

    // 启用中断
    ps2_write_command(PS2_CMD_READ_CONFIG);
    uint8_t config = ps2_read_data();
    config |= 0x02; // 启用端口2中断
    ps2_write_command(PS2_CMD_WRITE_CONFIG);
    ps2_write_data(config);

    ps2_state.mouse_cycle = 0;

    ps2_mouse_set_callback(ps2_mouse_callback);

    regist_input_dev_arg_t arg = {0};
    arg.uevent_append = "ID_INPUT_MOUSE=1";
    arg.from = INPUT_FROM_PS2;
    input_dev_desc_set_property(&arg, INPUT_PROP_POINTER);
    input_dev_desc_set_key(&arg, BTN_LEFT);
    input_dev_desc_set_key(&arg, BTN_RIGHT);
    input_dev_desc_set_key(&arg, BTN_MIDDLE);
    input_dev_desc_set_rel(&arg, REL_X);
    input_dev_desc_set_rel(&arg, REL_Y);
    input_dev_desc_set_rel(&arg, REL_WHEEL);
    ps2_mouse_input_event = system_abi->regist_input_dev("ps2mouse", &arg);

    irq_regist_irq(
        PS2_MOUSE_INTERRUPT_VECTOR,
        (void (*)(uint64_t, void *, struct pt_regs *))ps2_interrupt_handler, 12,
        NULL, &apic_controller, "PS/2 Mouse", 0);

    return true;
}

// 处理键盘数据
static void ps2_handle_keyboard_data(uint8_t data) {
    ps2_keyboard_event_t event = {0};

    if (data == 0xE0) {
        ps2_state.keyboard_extended = true;
        return;
    }

    event.is_extended = ps2_state.keyboard_extended;
    event.pressed = !(data & 0x80);
    event.scancode = data & 0x7F;

    ps2_state.keyboard_extended = false;

    if (ps2_state.keyboard_callback) {
        ps2_state.keyboard_callback(event);
    }
}

// 处理鼠标数据
static void ps2_handle_mouse_data(uint8_t data) {
    ps2_state.mouse_packet[ps2_state.mouse_cycle++] = data;

    // 标准鼠标：3字节
    // 带滚轮鼠标：4字节
    uint8_t packet_size = ps2_state.mouse_has_wheel ? 4 : 3;

    if (ps2_state.mouse_cycle < packet_size) {
        return;
    }

    ps2_state.mouse_cycle = 0;

    // 验证第一个字节
    if (!(ps2_state.mouse_packet[0] & 0x08)) {
        return; // 无效数据包
    }

    // 解析数据包
    ps2_mouse_event_t event = {0};

    event.left_button = ps2_state.mouse_packet[0] & 0x01;
    event.right_button = ps2_state.mouse_packet[0] & 0x02;
    event.middle_button = ps2_state.mouse_packet[0] & 0x04;
    event.x_overflow = ps2_state.mouse_packet[0] & 0x40;
    event.y_overflow = ps2_state.mouse_packet[0] & 0x80;

    // X和Y移动（9位有符号数）
    event.x = ps2_state.mouse_packet[1];
    if (ps2_state.mouse_packet[0] & 0x10) {
        event.x |= 0xFF00; // 符号扩展
    }

    event.y = ps2_state.mouse_packet[2];
    if (ps2_state.mouse_packet[0] & 0x20) {
        event.y |= 0xFF00; // 符号扩展
    }

    // Y轴反向（PS/2坐标系）
    event.y = -event.y;

    // 滚轮数据
    if (ps2_state.mouse_has_wheel) {
        event.z = (int8_t)(ps2_state.mouse_packet[3] & 0x0F);
        if (event.z & 0x08) {
            event.z |= 0xF0; // 符号扩展
        }
    }

    if (ps2_state.mouse_callback) {
        ps2_state.mouse_callback(event);
    }
}

// 中断处理函数
void ps2_interrupt_handler() {
    uint8_t status = io_in8(PS2_STATUS_PORT);

    if (!(status & 0x01)) {
        return; // 没有数据
    }

    uint8_t data = io_in8(PS2_DATA_PORT);

    // 检查数据来自哪个端口
    if (status & 0x20) {
        // 来自端口2（鼠标）
        ps2_handle_mouse_data(data);
    } else {
        // 来自端口1（键盘）
        ps2_handle_keyboard_data(data);
    }
}

// 设置回调函数
void ps2_keyboard_set_callback(ps2_keyboard_callback_t callback) {
    ps2_state.keyboard_callback = callback;
}

void ps2_mouse_set_callback(ps2_mouse_callback_t callback) {
    ps2_state.mouse_callback = callback;
}

bool ps2_mouse_has_wheel(void) { return ps2_state.mouse_has_wheel; }
