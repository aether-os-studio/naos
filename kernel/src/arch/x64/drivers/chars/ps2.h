#pragma once

#include <libs/klibc.h>

// PS/2 端口定义
#define PS2_DATA_PORT 0x60
#define PS2_STATUS_PORT 0x64
#define PS2_COMMAND_PORT 0x64

// PS/2 控制器命令
#define PS2_CMD_READ_CONFIG 0x20
#define PS2_CMD_WRITE_CONFIG 0x60
#define PS2_CMD_DISABLE_PORT2 0xA7
#define PS2_CMD_ENABLE_PORT2 0xA8
#define PS2_CMD_TEST_PORT2 0xA9
#define PS2_CMD_TEST_CONTROLLER 0xAA
#define PS2_CMD_TEST_PORT1 0xAB
#define PS2_CMD_DISABLE_PORT1 0xAD
#define PS2_CMD_ENABLE_PORT1 0xAE
#define PS2_CMD_WRITE_PORT2 0xD4

// 设备命令
#define PS2_DEV_RESET 0xFF
#define PS2_DEV_ENABLE 0xF4
#define PS2_DEV_DISABLE 0xF5
#define PS2_DEV_SET_DEFAULTS 0xF6
#define PS2_DEV_IDENTIFY 0xF2
#define PS2_DEV_SET_SAMPLE_RATE 0xF3

// 响应码
#define PS2_ACK 0xFA
#define PS2_RESEND 0xFE
#define PS2_ERROR 0xFC

void ps2_interrupt_handler();

// 键盘扫描码
typedef struct {
    uint8_t scancode;
    bool pressed;     // true=按下, false=释放
    bool is_extended; // E0扩展码
} ps2_keyboard_event_t;

// 鼠标数据
typedef struct {
    int16_t x; // X轴移动
    int16_t y; // Y轴移动
    int8_t z;  // 滚轮移动（如果支持）
    bool left_button;
    bool right_button;
    bool middle_button;
    bool x_overflow;
    bool y_overflow;
} ps2_mouse_event_t;

// 回调函数类型
typedef void (*ps2_keyboard_callback_t)(ps2_keyboard_event_t event);
typedef void (*ps2_mouse_callback_t)(ps2_mouse_event_t event);

void ps2_keyboard_set_callback(ps2_keyboard_callback_t callback);
void ps2_mouse_set_callback(ps2_mouse_callback_t callback);

size_t kb_event_bit(void *data, uint64_t request, void *arg);
size_t mouse_event_bit(void *data, uint64_t request, void *arg);

bool ps2_init(void);
bool ps2_keyboard_init(void);
bool ps2_mouse_init(void);
