#include "mt7921.h"

#include <arch/arch.h>

void mt7921_delay_us(uint64_t us) {
    uint64_t start = nano_time();

    while ((nano_time() - start) < us * 1000ULL) {
        arch_pause();
    }
}

void mt7921_delay_ms(uint64_t ms) { mt7921_delay_us(ms * 1000ULL); }

bool mt7921_wait_reg_mask(mt7921_priv_t *priv, uint32_t addr, uint32_t mask,
                          uint32_t want, uint64_t timeout_ms,
                          uint64_t interval_us) {
    uint64_t deadline = nano_time() + timeout_ms * 1000000ULL;

    while (nano_time() < deadline) {
        if ((mt7921_read_reg(priv, addr) & mask) == want) {
            return true;
        }

        mt7921_delay_us(interval_us ? interval_us : 1);
    }

    printk("mt7921: timed out waiting reg 0x%08x mask 0x%08x -> 0x%08x\n", addr,
           mask, want);
    return false;
}

int mt7921_vendor_request(mt7921_priv_t *priv, uint8_t req, uint8_t req_type,
                          uint16_t value, uint16_t index, void *buf,
                          size_t len) {
    usb_ctrl_request_t ctrl = {
        .bRequestType = req_type,
        .bRequest = req,
        .wValue = value,
        .wIndex = index,
        .wLength = (uint16_t)len,
    };
    int ret;

    mutex_lock(&priv->usb_ctrl_mtx);
    ret = usb_send_default_control(priv->usbdev->defpipe, &ctrl, buf);
    mutex_unlock(&priv->usb_ctrl_mtx);

    return ret;
}

uint32_t mt7921_read_uhw_reg(mt7921_priv_t *priv, uint32_t addr) {
    uint32_t val = 0;

    mt7921_vendor_request(priv, MT_VEND_DEV_MODE,
                          USB_DIR_IN | MT_USB_TYPE_UHW_VENDOR, addr >> 16,
                          addr & 0xffffU, &val, sizeof(val));
    return val;
}

void mt7921_write_uhw_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t val) {
    mt7921_vendor_request(priv, MT_VEND_WRITE,
                          USB_DIR_OUT | MT_USB_TYPE_UHW_VENDOR, addr >> 16,
                          addr & 0xffffU, &val, sizeof(val));
}

uint32_t mt7921_read_reg(mt7921_priv_t *priv, uint32_t addr) {
    uint32_t val = 0;

    mt7921_vendor_request(priv, MT_VEND_READ_EXT,
                          USB_DIR_IN | MT_USB_TYPE_VENDOR, addr >> 16,
                          addr & 0xffffU, &val, sizeof(val));
    return val;
}

void mt7921_write_reg(mt7921_priv_t *priv, uint32_t addr, uint32_t val) {
    mt7921_vendor_request(priv, MT_VEND_WRITE_EXT,
                          USB_DIR_OUT | MT_USB_TYPE_VENDOR, addr >> 16,
                          addr & 0xffffU, &val, sizeof(val));
}
