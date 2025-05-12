#pragma once

#include <libs/klibc.h>

struct kui_window;
typedef struct kui_window kui_window_t;

typedef struct
{
    uint8_t buf[3], phase;
    int x, y, btn;
    char roll;
    bool left;
    bool center;
    bool right;
    kui_window_t *current_moving_window;
} mouse_dec;

void get_mouse_xy(int32_t *x, int32_t *y);
bool mouse_click_left();
bool mouse_click_right();

void mouse_init();

size_t mouse_event_bit(void *data, uint64_t request, void *arg);

/*
 * Relative axes
 */

#define REL_X 0x00
#define REL_Y 0x01
#define REL_Z 0x02
#define REL_RX 0x03
#define REL_RY 0x04
#define REL_RZ 0x05
#define REL_HWHEEL 0x06
#define REL_DIAL 0x07
#define REL_WHEEL 0x08
#define REL_MISC 0x09
/*
 * 0x0a is reserved and should not be used in input drivers.
 * It was used by HID as REL_MISC+1 and userspace needs to detect if
 * the next REL_* event is correct or is just REL_MISC + n.
 * We define here REL_RESERVED so userspace can rely on it and detect
 * the situation described above.
 */
#define REL_RESERVED 0x0a
#define REL_WHEEL_HI_RES 0x0b
#define REL_HWHEEL_HI_RES 0x0c
#define REL_MAX 0x0f
#define REL_CNT (REL_MAX + 1)

/*
 * Absolute axes
 */

#define ABS_X 0x00
#define ABS_Y 0x01
#define ABS_Z 0x02
#define ABS_RX 0x03
#define ABS_RY 0x04
#define ABS_RZ 0x05
#define ABS_THROTTLE 0x06
#define ABS_RUDDER 0x07
#define ABS_WHEEL 0x08
#define ABS_GAS 0x09
#define ABS_BRAKE 0x0a
#define ABS_HAT0X 0x10
#define ABS_HAT0Y 0x11
#define ABS_HAT1X 0x12
#define ABS_HAT1Y 0x13
#define ABS_HAT2X 0x14
#define ABS_HAT2Y 0x15
#define ABS_HAT3X 0x16
#define ABS_HAT3Y 0x17
#define ABS_PRESSURE 0x18
#define ABS_DISTANCE 0x19
#define ABS_TILT_X 0x1a
#define ABS_TILT_Y 0x1b
#define ABS_TOOL_WIDTH 0x1c

#define ABS_VOLUME 0x20
#define ABS_PROFILE 0x21

#define ABS_MISC 0x28
