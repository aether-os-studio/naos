#include <drivers/usb/hid/hid.h>
#include <drivers/usb/hid/kbd.h>
#include <mm/mm.h>

KEY_EVENT_RING KEY_RING;

void KeyEvent(KEY_EVENT_RING *ring, uint8_t keycode)
{
    if (((ring->NID + 1) % ring->CNT) != ring->EID)
    {
        ring->RNG[ring->NID++] = keycode;
        ring->NID %= ring->CNT;
    }
}

uint8_t KeyNext(KEY_EVENT_RING *ring)
{
    if (ring->EID != ring->NID)
    {
        uint8_t keycode = ring->RNG[ring->EID++];
        ring->EID %= ring->CNT;
        return keycode;
    }
    return 0;
}

void CreateKeyEventRing(KEY_EVENT_RING *ring)
{
    uint64_t paddr = (uint64_t)alloc_frames_bytes(DEFAULT_PAGE_SIZE);
    ring->RNG = (uint8_t *)paddr;
    ring->CNT = 4096;
    ring->NID = ring->EID = 0;
}
