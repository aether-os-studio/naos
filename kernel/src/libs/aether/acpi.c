#include <libs/aether/acpi.h>
#include <drivers/bus/pci.h>
#include <boot/boot.h>
#include <mod/dlinker.h>
#include <uacpi/namespace.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>

#define ACPI_DSM_MAX_PCI_DEPTH 32

static int acpi_extract_object(uacpi_object *obj, void *buffer,
                               uint32_t buffer_size, uint32_t *data_size);

static int acpi_extract_integer(uacpi_object *obj, void *buffer,
                                uint32_t buffer_size, uint32_t *data_size) {
    uacpi_u64 value = 0;
    if (uacpi_object_get_integer(obj, &value) != UACPI_STATUS_OK) {
        return -EINVAL;
    }

    *data_size = (value & ~0xFFFFFFFFULL) ? sizeof(value) : sizeof(uint32_t);
    if (buffer_size < *data_size) {
        return -ENOBUFS;
    }

    memcpy(buffer, &value, *data_size);
    return 0;
}

static int acpi_extract_buffer_like(uacpi_object *obj, void *buffer,
                                    uint32_t buffer_size, uint32_t *data_size) {
    uacpi_data_view view = {0};
    if (uacpi_object_get_string_or_buffer(obj, &view) != UACPI_STATUS_OK) {
        return -EINVAL;
    }

    *data_size = (uint32_t)view.length;
    if (buffer_size < *data_size) {
        return -ENOBUFS;
    }

    if (*data_size != 0) {
        memcpy(buffer, view.bytes, *data_size);
    }
    return 0;
}

static int acpi_extract_package(uacpi_object *obj, void *buffer,
                                uint32_t buffer_size, uint32_t *data_size) {
    uacpi_object_array arr = {0};
    if (uacpi_object_get_package(obj, &arr) != UACPI_STATUS_OK) {
        return -EINVAL;
    }

    uint32_t total = 0;
    for (uacpi_size i = 0; i < arr.count; i++) {
        uint32_t elem_size = 0;
        if (total > buffer_size) {
            *data_size = total;
            return -ENOBUFS;
        }

        int ret = acpi_extract_object(arr.objects[i], (uint8_t *)buffer + total,
                                      buffer_size - total, &elem_size);
        if (ret != 0) {
            *data_size = total;
            return ret;
        }

        total += elem_size;
    }

    *data_size = total;
    return 0;
}

static int acpi_extract_object(uacpi_object *obj, void *buffer,
                               uint32_t buffer_size, uint32_t *data_size) {
    if (!obj || !data_size) {
        return -EINVAL;
    }

    switch (uacpi_object_get_type(obj)) {
    case UACPI_OBJECT_INTEGER:
        return acpi_extract_integer(obj, buffer, buffer_size, data_size);
    case UACPI_OBJECT_BUFFER:
    case UACPI_OBJECT_STRING:
        return acpi_extract_buffer_like(obj, buffer, buffer_size, data_size);
    case UACPI_OBJECT_PACKAGE:
        return acpi_extract_package(obj, buffer, buffer_size, data_size);
    case UACPI_OBJECT_UNINITIALIZED:
        *data_size = 0;
        return 0;
    default:
        return -ENOTSUP;
    }
}

static int acpi_collect_pci_path(uacpi_namespace_node *node, uint32_t path[],
                                 uint32_t *path_len, bool *has_segment,
                                 uint16_t *segment) {
    if (!node || !path || !path_len || !has_segment || !segment) {
        return -EINVAL;
    }

    uacpi_namespace_node *iter = node;
    uint32_t count = 0;
    *has_segment = false;
    *segment = 0;

    while (iter != UACPI_NULL) {
        uacpi_u64 seg = 0;
        if (!(*has_segment) &&
            uacpi_eval_simple_integer(iter, "_SEG", &seg) == UACPI_STATUS_OK) {
            *has_segment = true;
            *segment = (uint16_t)seg;
        }

        uacpi_u64 adr = 0;
        if (uacpi_eval_simple_integer(iter, "_ADR", &adr) == UACPI_STATUS_OK) {
            if (count >= ACPI_DSM_MAX_PCI_DEPTH || adr > 0xFFFFFFFFULL) {
                return -EINVAL;
            }
            path[count++] = (uint32_t)adr;
        }

        iter = uacpi_namespace_node_parent(iter);
    }

    if (count == 0) {
        return -ENOENT;
    }

    for (uint32_t i = 0; i < count / 2; i++) {
        uint32_t tmp = path[i];
        path[i] = path[count - 1 - i];
        path[count - 1 - i] = tmp;
    }

    *path_len = count;
    return 0;
}

static pci_device_t *acpi_find_bridge_for_child_bus(uint16_t segment,
                                                    uint8_t child_bus,
                                                    uint8_t slot,
                                                    uint8_t func) {
    for (uint32_t i = 0; i < pci_device_number; i++) {
        pci_device_t *pdev = pci_devices[i];
        if (!pdev) {
            continue;
        }

        if (pdev->segment != segment || pdev->slot != slot ||
            pdev->func != func) {
            continue;
        }

        if (!pdev->op || ((pdev->header_type & 0x7f) != 0x01)) {
            continue;
        }

        uint8_t secondary = pdev->op->read8(pdev->bus, pdev->slot, pdev->func,
                                            pdev->segment, 0x19);
        if (secondary == child_bus) {
            return pdev;
        }
    }

    return NULL;
}

static bool acpi_namespace_node_matches_pci(uacpi_namespace_node *node,
                                            uint16_t segment, uint8_t bus,
                                            uint8_t slot, uint8_t func) {
    uint32_t path[ACPI_DSM_MAX_PCI_DEPTH] = {0};
    uint32_t path_len = 0;
    bool has_segment = false;
    uint16_t segment_from_ns = 0;
    if (acpi_collect_pci_path(node, path, &path_len, &has_segment,
                              &segment_from_ns) != 0) {
        return false;
    }

    if (has_segment && segment_from_ns != segment) {
        return false;
    }

    uint32_t leaf = path[path_len - 1];
    uint32_t leaf_slot = (leaf >> 16) & 0xFFFF;
    uint32_t leaf_func = leaf & 0xFFFF;
    if (leaf_slot != slot || leaf_func != func || leaf_slot > 31 ||
        leaf_func > 7) {
        return false;
    }

    if (!pci_find_bdfs(bus, slot, func, segment)) {
        return false;
    }

    uint8_t child_bus = bus;
    for (int32_t i = (int32_t)path_len - 2; i >= 0; i--) {
        uint32_t adr = path[i];
        uint32_t path_slot = (adr >> 16) & 0xFFFF;
        uint32_t path_func = adr & 0xFFFF;
        if (path_slot > 31 || path_func > 7) {
            return false;
        }

        pci_device_t *bridge = acpi_find_bridge_for_child_bus(
            segment, child_bus, (uint8_t)path_slot, (uint8_t)path_func);
        if (!bridge) {
            if (i == 0) {
                continue;
            }
            return false;
        }

        child_bus = bridge->bus;
    }

    return true;
}

typedef struct acpi_pci_find_ctx {
    uint16_t segment;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uacpi_namespace_node *node;
} acpi_pci_find_ctx_t;

static uacpi_iteration_decision
acpi_find_pci_node_cb(void *user, uacpi_namespace_node *node, uacpi_u32 depth) {
    (void)depth;
    acpi_pci_find_ctx_t *ctx = user;
    if (!ctx || !node || ctx->node) {
        return UACPI_ITERATION_DECISION_BREAK;
    }

    uacpi_object_type type;
    if (uacpi_namespace_node_type(node, &type) != UACPI_STATUS_OK ||
        type != UACPI_OBJECT_DEVICE) {
        return UACPI_ITERATION_DECISION_CONTINUE;
    }

    uacpi_u64 adr = 0;
    if (uacpi_eval_simple_integer(node, "_ADR", &adr) != UACPI_STATUS_OK ||
        adr > 0xFFFFFFFFULL) {
        return UACPI_ITERATION_DECISION_CONTINUE;
    }

    if ((((uint32_t)adr >> 16) & 0xFFFF) != ctx->slot ||
        ((uint32_t)adr & 0xFFFF) != ctx->func) {
        return UACPI_ITERATION_DECISION_CONTINUE;
    }

    if (!acpi_namespace_node_matches_pci(node, ctx->segment, ctx->bus,
                                         ctx->slot, ctx->func)) {
        return UACPI_ITERATION_DECISION_CONTINUE;
    }

    ctx->node = node;
    return UACPI_ITERATION_DECISION_BREAK;
}

static uacpi_namespace_node *acpi_find_pci_namespace_node(uint16_t segment,
                                                          uint8_t bus,
                                                          uint8_t slot,
                                                          uint8_t func) {
    uacpi_namespace_node *root = uacpi_namespace_root();
    if (!root) {
        return UACPI_NULL;
    }

    acpi_pci_find_ctx_t ctx = {
        .segment = segment,
        .bus = bus,
        .slot = slot,
        .func = func,
        .node = UACPI_NULL,
    };

    uacpi_namespace_for_each_child_simple(root, acpi_find_pci_node_cb, &ctx);
    return ctx.node;
}

uint64_t get_rsdp_paddr() { return boot_get_acpi_rsdp(); }

int acpi_eval_dsm_for_pci(uint16_t segment, uint8_t bus, uint8_t slot,
                          uint8_t func, const uint8_t guid[16],
                          uint32_t revision, bool use_nvpcf_scope,
                          uint32_t sub_function, const void *arg3,
                          uint16_t arg3_size, bool arg3_is_integer,
                          uint32_t *out_status, void *out_data,
                          uint32_t *inout_size) {
    if (!guid || !arg3 || !out_data || !inout_size) {
        return -EINVAL;
    }

    uacpi_namespace_node *target = UACPI_NULL;
    if (!use_nvpcf_scope) {
        target = acpi_find_pci_namespace_node(segment, bus, slot, func);
        if (!target) {
            return -ENOENT;
        }
    }

    uacpi_object *args_buf[4] = {UACPI_NULL, UACPI_NULL, UACPI_NULL,
                                 UACPI_NULL};
    uacpi_object_array args = {
        .objects = args_buf,
        .count = 4,
    };
    uacpi_object *ret_obj = UACPI_NULL;
    int ret = -EIO;

    uacpi_data_view guid_view = {
        .const_bytes = guid,
        .length = 16,
    };
    args_buf[0] = uacpi_object_create_buffer(guid_view);
    args_buf[1] = uacpi_object_create_integer(revision);
    args_buf[2] = uacpi_object_create_integer(sub_function);
    if (arg3_is_integer) {
        args_buf[3] = uacpi_object_create_integer(*(const uint32_t *)arg3);
    } else {
        uacpi_data_view arg3_view = {
            .const_bytes = arg3,
            .length = arg3_size,
        };
        args_buf[3] = uacpi_object_create_buffer(arg3_view);
    }

    for (uint32_t i = 0; i < 4; i++) {
        if (!args_buf[i]) {
            ret = -ENOMEM;
            goto out;
        }
    }

    uacpi_status status;
    if (use_nvpcf_scope) {
        status = uacpi_eval(UACPI_NULL, "\\_SB.NPCF._DSM", &args, &ret_obj);
    } else {
        status = uacpi_eval(target, "_DSM", &args, &ret_obj);
    }
    if (status != UACPI_STATUS_OK) {
        ret = (status == UACPI_STATUS_NOT_FOUND) ? -ENOTSUP : -EIO;
        goto out;
    }
    if (!ret_obj) {
        *inout_size = 0;
        ret = 0;
        goto out;
    }

    if (out_status) {
        *out_status = 0;
        switch (uacpi_object_get_type(ret_obj)) {
        case UACPI_OBJECT_INTEGER: {
            uacpi_u64 value = 0;
            if (uacpi_object_get_integer(ret_obj, &value) == UACPI_STATUS_OK) {
                *out_status = (uint32_t)value;
            }
            break;
        }
        case UACPI_OBJECT_BUFFER:
        case UACPI_OBJECT_STRING: {
            uacpi_data_view view = {0};
            if (uacpi_object_get_string_or_buffer(ret_obj, &view) ==
                    UACPI_STATUS_OK &&
                view.length >= 4) {
                const uint8_t *buf = view.const_bytes;
                *out_status = ((uint32_t)buf[0]) | (((uint32_t)buf[1]) << 8) |
                              (((uint32_t)buf[2]) << 16) |
                              (((uint32_t)buf[3]) << 24);
            }
            break;
        }
        default:
            break;
        }
    }

    uint32_t required = 0;
    ret = acpi_extract_object(ret_obj, out_data, *inout_size, &required);
    *inout_size = required;

out:
    if (ret_obj) {
        uacpi_object_unref(ret_obj);
    }
    for (uint32_t i = 0; i < 4; i++) {
        if (args_buf[i]) {
            uacpi_object_unref(args_buf[i]);
        }
    }

    return ret;
}

EXPORT_SYMBOL(get_rsdp_paddr);
EXPORT_SYMBOL(acpi_eval_dsm_for_pci);
