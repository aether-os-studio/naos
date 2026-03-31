#include "mt7921.h"

static const usb_device_id_t mt7921_ids[] = {
    USB_DEVICE(0x0e8d, 0x7961), USB_DEVICE(0x3574, 0x6211),
    USB_DEVICE(0x0846, 0x9060), USB_DEVICE(0x0846, 0x9065),
    USB_DEVICE(0x35bc, 0x0107), {0},
};

static int mt7921_probe(usb_device_t *usbdev, usb_device_interface_t *iface) {
    mt7921_priv_t *priv;
    uint32_t misc;
    int ret;

    priv = calloc(1, sizeof(*priv));
    if (!priv) {
        return -ENOMEM;
    }

    priv->usbdev = usbdev;
    priv->antenna_mask = 0x1;
    mutex_init(&priv->usb_ctrl_mtx);
    mutex_init(&priv->mcu_mutex);
    spin_init(&priv->resp_lock);
    spin_init(&priv->data_lock);
    spin_init(&priv->scan_lock);

    ret = mt7921_usb_init(priv, iface);
    if (ret) {
        goto err_free;
    }

    misc = mt7921_read_reg(priv, MT_CONN_ON_MISC);
    if ((misc & MT_TOP_MISC2_FW_N9_RDY_MASK) ==
        (MT_TOP_MISC2_FW_N9_RDY_VALUE << MT_TOP_MISC2_FW_N9_RDY_SHIFT)) {
        ret = mt7921_wfsys_reset(priv);
        if (ret) {
            goto err_usb;
        }
    }

    ret = mt7921_mcu_power_on(priv);
    if (ret) {
        goto err_usb;
    }

    ret = mt7921_usb_start_rx(priv);
    if (ret) {
        goto err_usb;
    }

    ret = mt7921_dma_init(priv, false);
    if (ret) {
        goto err_rx;
    }

    mt7921_write_reg(priv, MT_UDMA_TX_QSEL,
                     mt7921_read_reg(priv, MT_UDMA_TX_QSEL) | MT_FW_DL_EN);
    ret = mt7921_run_firmware(priv);
    mt7921_write_reg(priv, MT_UDMA_TX_QSEL,
                     mt7921_read_reg(priv, MT_UDMA_TX_QSEL) & ~MT_FW_DL_EN);
    if (ret) {
        goto err_rx;
    }

    ret = mt7921_wifi_register(priv);
    if (ret) {
        goto err_rx;
    }

    usbdev->desc = priv;
    printk("mt7921: initialized %02x:%02x:%02x:%02x:%02x:%02x\n",
           priv->macaddr[0], priv->macaddr[1], priv->macaddr[2],
           priv->macaddr[3], priv->macaddr[4], priv->macaddr[5]);

    return 0;

err_rx:
    mt7921_usb_stop_rx(priv);
err_usb:
    mt7921_usb_cleanup(priv);
err_free:
    free(priv);
    return ret;
}

static int mt7921_remove(usb_device_t *usbdev) {
    mt7921_priv_t *priv;

    if (!usbdev || !usbdev->desc) {
        return 0;
    }

    priv = (mt7921_priv_t *)usbdev->desc;
    usbdev->desc = NULL;

    mt7921_wifi_remove(priv);
    mt7921_usb_stop_rx(priv);
    mt7921_usb_cleanup(priv);
    /*
     * Keep priv allocated for now. netdev/wifi teardown is not yet complete and
     * sockets/lwIP may still hold references while hot-unplug is unsupported.
     */
    // free(priv);
    return 0;
}

static usb_driver_t mt7921_driver = {
    .name = "mt7921",
    .id_table = mt7921_ids,
    .priority = 0,
    .probe = mt7921_probe,
    .remove = mt7921_remove,
};

int dlmain() {
    regist_usb_driver(&mt7921_driver);
    return 0;
}
