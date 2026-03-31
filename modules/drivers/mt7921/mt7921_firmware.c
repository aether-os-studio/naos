#include "mt7921.h"

#include <fs/vfs/vfs.h>

int mt7921_mcu_get_nic_capability(mt7921_priv_t *priv);
int mt7921_mcu_fw_log_2_host(mt7921_priv_t *priv, uint8_t ctrl);
int mt7921_send_patch_firmware(mt7921_priv_t *priv, uint8_t *data, size_t size);
int mt7921_send_ram_firmware(mt7921_priv_t *priv, uint8_t *data, size_t size);

static int mt7921_load_clc(mt7921_priv_t *priv) {
    (void)priv;
    return 0;
}

static int mt7921_get_firmware_blob(const char *path, uint8_t **data,
                                    size_t *size) {
    vfs_node_t *node;
    uint8_t *buf;

    node = vfs_open(path, 0);
    if (!node) {
        printk("mt7921: failed to open firmware %s\n", path);
        return -ENOENT;
    }

    buf = malloc(node->size);
    if (!buf) {
        return -ENOMEM;
    }

    vfs_read(node, buf, 0, node->size);
    *data = buf;
    *size = node->size;
    return 0;
}

static int mt7921_wait_fw_ready(mt7921_priv_t *priv) {
    if (!mt7921_wait_reg_mask(
            priv, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_N9_RDY_MASK,
            MT_TOP_MISC2_FW_N9_RDY_VALUE << MT_TOP_MISC2_FW_N9_RDY_SHIFT, 1500,
            1000)) {
        printk("mt7921: timed out waiting firmware ready\n");
        return -ETIMEDOUT;
    }

    return 0;
}

int mt7921_run_firmware(mt7921_priv_t *priv) {
    uint8_t *patch_data = NULL;
    uint8_t *ram_data = NULL;
    size_t patch_size = 0;
    size_t ram_size = 0;
    int ret;

    ret = mt7921_get_firmware_blob("/lib/firmware/" MT7921_ROM_PATCH,
                                   &patch_data, &patch_size);
    if (ret) {
        goto out;
    }

    ret = mt7921_send_patch_firmware(priv, patch_data, patch_size);
    if (ret) {
        printk("mt7921: patch download failed\n");
        goto out;
    }

    ret = mt7921_get_firmware_blob("/lib/firmware/" MT7921_FIRMWARE_WM,
                                   &ram_data, &ram_size);
    if (ret) {
        goto out;
    }

    ret = mt7921_send_ram_firmware(priv, ram_data, ram_size);
    if (ret) {
        printk("mt7921: RAM firmware download failed\n");
        goto out;
    }

    ret = mt7921_wait_fw_ready(priv);
    if (ret) {
        goto out;
    }

    ret = mt7921_mcu_get_nic_capability(priv);
    if (ret) {
        printk("mt7921: failed to read NIC capability\n");
        goto out;
    }

    ret = mt7921_load_clc(priv);
    if (ret) {
        goto out;
    }

    ret = mt7921_mcu_fw_log_2_host(priv, 1);
    if (ret) {
        printk("mt7921: failed to enable firmware log\n");
    }

out:
    free(patch_data);
    free(ram_data);
    return ret;
}
