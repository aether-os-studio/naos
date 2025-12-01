#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/sys.h>
#include <drivers/input.h>
#include <libs/keys.h>

extern void handle_kb_event(uint8_t scan_code, bool pressed);
extern void handle_mouse_event(uint8_t flag, int8_t x, int8_t y, int8_t z);

static struct {
    ps2_keyboard_callback_t keyboard_callback;
    ps2_mouse_callback_t mouse_callback;

    // 键盘状态
    bool keyboard_extended;

    // 鼠标状态
    uint8_t mouse_cycle;
    uint8_t mouse_packet[4];
    bool mouse_has_wheel;

    bool port1_available;
    bool port2_available;
} ps2_state = {0};

// 等待可以写入
static bool ps2_wait_write(void) {
    uint32_t timeout = nanoTime() + 1000ULL * 1000000ULL;
    while (timeout > nanoTime()) {
        if ((io_in8(PS2_STATUS_PORT) & 0x02) == 0) {
            return true;
        }
    }
    return false;
}

// 等待可以读取
static bool ps2_wait_read(void) {
    uint32_t timeout = nanoTime() + 1000ULL * 1000000ULL;
    while (timeout > nanoTime()) {
        if (io_in8(PS2_STATUS_PORT) & 0x01) {
            return true;
        }
    }
    return false;
}

// 读取数据
static uint8_t ps2_read_data(void) {
    ps2_wait_read();
    return io_in8(PS2_DATA_PORT);
}

// 写入命令
static void ps2_write_command(uint8_t cmd) {
    ps2_wait_write();
    io_out8(PS2_COMMAND_PORT, cmd);
}

// 写入数据
static void ps2_write_data(uint8_t data) {
    ps2_wait_write();
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

void ps2_keyboard_callback(ps2_keyboard_event_t event) {
    handle_kb_scancode(event.scancode, event.pressed);
}

void ps2_mouse_callback(ps2_mouse_event_t event) {
    uint8_t flags = 0;
    if (event.left_button)
        flags |= (1 << 0);
    if (event.right_button)
        flags |= (1 << 1);
    if (event.middle_button)
        flags |= (1 << 2);

    handle_mouse_event(flags, event.x, event.y, -event.z);
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

dev_input_event_t *kb_input_event = NULL;
dev_input_event_t *mouse_input_event = NULL;

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

    kb_input_event = regist_input_dev("ps2kbd", "ID_INPUT_KEYBOARD=1",
                                      INPUT_FROM_PS2, kb_event_bit);

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

    mouse_input_event = regist_input_dev("ps2mouse", "ID_INPUT_MOUSE=1",
                                         INPUT_FROM_PS2, mouse_event_bit);

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

size_t kb_event_bit(void *data, uint64_t request, void *arg) {
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    size_t ret = (size_t)-ENOSYS;
    switch (number) {
    // case 0x03:
    // {
    //     struct input_repeat_params *params = arg;
    //     params->delay = 500;
    //     params->period = 50;
    //     break;
    // }
    case 0x20: {
        size_t out = (1 << EV_KEY);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_SW):
    case (0x20 + EV_MSC):
    case (0x20 + EV_SND):
    case (0x20 + EV_LED):
    case (0x20 + EV_REL):
    case (0x20 + EV_ABS): {
        *(size_t *)arg = 0;
        ret = MIN(sizeof(size_t), size);
        break;
    }
    case (0x20 + EV_FF): {
        *(size_t *)arg = 0;
        ret = MIN(16, size);
        break;
    }
    case (0x20 + EV_KEY): {
        uint8_t map[96] = {0};
        for (int i = KEY_ESC; i <= KEY_MENU; i++)
            map[i / 8] |= (1 << (i % 8));
        ret = MIN(96, size);
        memcpy(arg, map, ret);
        break;
    }
    case 0x18: // EVIOCGKEY()
    {
        uint8_t map[96];
        memset(map, 0, sizeof(map));
        ret = MIN(96, size);
        memcpy(arg, map, ret);
        break;
    }
    case 0x19: // EVIOCGLED()
        *(size_t *)arg = 0;
        ret = MIN(8, size);
        break;
    case 0x1b: // EVIOCGSW()
        *(size_t *)arg = 0;
        ret = MIN(8, size);
        break;
    case 0xa0:
        dev_input_event_t *event = data;
        event->clock_id = *(int *)arg;
        ret = 0;
        break;
    default:
        printk("kb_event_bit(): Unsupported ioctl: request = %#018lx\n",
               request);
        break;
    }

    return ret;
}

size_t mouse_event_bit(void *data, uint64_t request, void *arg) {
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    size_t ret = (size_t)-ENOSYS;
    switch (number) {
    // case 0x03:
    // {
    //     struct input_repeat_params *params = arg;
    //     params->delay = 500;
    //     params->period = 50;
    //     break;
    // }
    case 0x20: {
        size_t out = (1 << EV_KEY) | (1 << EV_REL);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_SW):
    case (0x20 + EV_MSC):
    case (0x20 + EV_SND):
    case (0x20 + EV_LED):
    case (0x20 + EV_ABS): {
        *(size_t *)arg = 0;
        ret = MIN(sizeof(size_t), size);
        break;
    }
    case (0x20 + EV_FF): {
        *(size_t *)arg = 0;
        ret = MIN(16, size);
        break;
    }
    case (0x20 + EV_REL): {
        size_t out = (1 << REL_X) | (1 << REL_Y) | (1 << REL_WHEEL);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_KEY): {
        uint8_t map[96] = {0};
        map[BTN_RIGHT / 8] |= (1 << (BTN_RIGHT % 8));
        map[BTN_LEFT / 8] |= (1 << (BTN_LEFT % 8));
        ret = MIN(96, size);
        memcpy(arg, map, ret);
        break;
    }
    case 0x18: // EVIOCGKEY()
        ret = MIN(96, size);
        break;
    case 0x19: // EVIOCGLED()
        ret = MIN(8, size);
        break;
    case 0x1b: // EVIOCGSW()
        ret = MIN(8, size);
        break;
    case 0xa0:
        dev_input_event_t *event = data;
        event->clock_id = *(int *)arg;
        ret = 0;
        break;
    default:
        printk("mouse_event_bit(): Unsupported ioctl: request = %#018lx\n",
               request);
        break;
    }

    return ret;
}
