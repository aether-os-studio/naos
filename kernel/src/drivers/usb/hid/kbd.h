#pragma once

#include <drivers/usb/xhci.h>

typedef struct _KEY_EVENT_RING
{
    uint8_t *RNG;
    uint16_t CNT;
    uint16_t NID;
    uint16_t EID;
} KEY_EVENT_RING;

extern KEY_EVENT_RING KEY_RING;

void KeyEvent(KEY_EVENT_RING *, uint8_t);
uint8_t KeyNext(KEY_EVENT_RING *);
void CreateKeyEventRing(KEY_EVENT_RING *);
