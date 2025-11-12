#include <boot/boot.h>
#include <drivers/fdt/fdt.h>
#include <mm/mm.h>
#include <libs/aether/fdt.h>

#if !defined(__x86_64__)

struct fdt_context g_fdt_ctx = {0};

/**
 * 获取属性名称
 */
static const char *fdt_get_property_name(uint32_t nameoff) {
    return g_fdt_ctx.dt_strings + fdt32_to_cpu(nameoff);
}

/**
 * 查找节点
 * @param path 节点路径
 * @return 节点在结构块中的偏移，失败返回-1
 */
int fdt_find_node(const char *path) {
    uint32_t *p = (uint32_t *)g_fdt_ctx.dt_struct;
    if (!p)
        return -1;

    int depth = 0;
    char current_path[256] = "";
    char node_name[128];

    if (path[0] != '/') {
        return -1;
    }

    while (1) {
        uint32_t tag = fdt32_to_cpu(*p++);

        switch (tag) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)p;
            int name_len = strlen(name);

            if (depth == 0) {
                strcpy(current_path, "/");
            } else {
                if (current_path[strlen(current_path) - 1] != '/') {
                    strcat(current_path, "/");
                }
                strcat(current_path, name);
            }

            /* 检查是否匹配 */
            if (strcmp(current_path, path) == 0) {
                return (uint8_t *)p - (uint8_t *)g_fdt_ctx.dt_struct - 4;
            }

            depth++;
            p = (uint32_t *)ALIGN_UP((uintptr_t)p + name_len + 1, 4);
        } break;

        case FDT_END_NODE:
            depth--;
            if (depth < 0) {
                return -1;
            }
            /* 更新current_path，移除最后一个节点 */
            {
                char *last_slash = strrchr(current_path, '/');
                if (last_slash && last_slash != current_path) {
                    *last_slash = '\0';
                }
            }
            break;

        case FDT_PROP: {
            struct fdt_property *prop = (struct fdt_property *)p;
            uint32_t len = fdt32_to_cpu(prop->len);
            p = (uint32_t *)ALIGN_UP(
                (uintptr_t)p + sizeof(struct fdt_property) + len, 4);
        } break;

        case FDT_NOP:
            break;

        case FDT_END:
            return -1;

        default:
            return -1;
        }
    }

    return -1;
}

/**
 * 获取节点的属性
 * @param node_offset 节点偏移
 * @param prop_name 属性名
 * @param len 返回属性长度
 * @return 属性值指针，失败返回NULL
 */
const void *fdt_get_property(int node_offset, const char *prop_name, int *len) {
    if (!g_fdt_ctx.dt_struct)
        return NULL;

    uint32_t *p = (uint32_t *)((uint8_t *)g_fdt_ctx.dt_struct + node_offset);
    uint32_t tag;
    int depth = 0;

    /* 跳过BEGIN_NODE标记和节点名 */
    tag = fdt32_to_cpu(*p++);
    if (tag != FDT_BEGIN_NODE) {
        return NULL;
    }

    const char *name = (const char *)p;
    p = (uint32_t *)ALIGN_UP((uintptr_t)p + strlen(name) + 1, 4);

    /* 查找属性 */
    while (1) {
        tag = fdt32_to_cpu(*p++);

        switch (tag) {
        case FDT_PROP: {
            struct fdt_property *prop = (struct fdt_property *)p;
            const char *pname = fdt_get_property_name(prop->nameoff);

            if (strcmp(pname, prop_name) == 0) {
                if (len) {
                    *len = fdt32_to_cpu(prop->len);
                }
                return (uint8_t *)p + sizeof(struct fdt_property);
            }

            uint32_t plen = fdt32_to_cpu(prop->len);
            p = (uint32_t *)ALIGN_UP(
                (uintptr_t)p + sizeof(struct fdt_property) + plen, 4);
        } break;

        case FDT_BEGIN_NODE:
            /* 进入子节点，不再搜索 */
            return NULL;

        case FDT_END_NODE:
            return NULL;

        case FDT_NOP:
            break;

        case FDT_END:
            return NULL;

        default:
            return NULL;
        }
    }

    return NULL;
}

/**
 * 获取32位整数属性值
 */
int fdt_get_property_u32(int node_offset, const char *prop_name,
                         uint32_t *value) {
    int len;
    const uint32_t *prop = fdt_get_property(node_offset, prop_name, &len);

    if (!prop || len != sizeof(uint32_t)) {
        return -1;
    }

    *value = fdt32_to_cpu(*prop);
    return 0;
}

/**
 * 获取64位整数属性值
 */
int fdt_get_property_u64(int node_offset, const char *prop_name,
                         uint64_t *value) {
    int len;
    const uint64_t *prop = fdt_get_property(node_offset, prop_name, &len);

    if (!prop || len != sizeof(uint64_t)) {
        return -1;
    }

    *value = fdt64_to_cpu(*prop);
    return 0;
}

/**
 * 获取字符串属性值
 */
const char *fdt_get_property_string(int node_offset, const char *prop_name) {
    int len;
    const char *prop = fdt_get_property(node_offset, prop_name, &len);

    if (!prop || len <= 0) {
        return NULL;
    }

    /* 确保字符串以null结尾 */
    if (prop[len - 1] != '\0') {
        return NULL;
    }

    return prop;
}

/**
 * 遍历所有设备树节点（示例回调）
 */
void fdt_walk_nodes(fdt_node_callback callback) {
    uint32_t *p = (uint32_t *)g_fdt_ctx.dt_struct;
    if (!p)
        return;
    int depth = 0;
    char path_stack[10][128]; /* 路径栈 */
    char current_path[256];

    strcpy(path_stack[0], "");

    while (1) {
        uint32_t tag = fdt32_to_cpu(*p);

        switch (tag) {
        case FDT_BEGIN_NODE: {
            int offset = (uint8_t *)p - (uint8_t *)g_fdt_ctx.dt_struct;
            p++;
            const char *name = (const char *)p;

            /* 构建路径 */
            if (depth == 0) {
                strcpy(current_path, "/");
                strcpy(path_stack[depth], "");
            } else {
                strcpy(current_path, "");
                for (int i = 0; i < depth; i++) {
                    if (strlen(path_stack[i]) > 0) {
                        strcat(current_path, "/");
                        strcat(current_path, path_stack[i]);
                    }
                }
                strcat(current_path, "/");
                strcat(current_path, name);
            }

            /* 调用回调 */
            if (callback) {
                callback(current_path, offset, depth);
            }

            strcpy(path_stack[depth], name);
            depth++;
            p = (uint32_t *)ALIGN_UP((uintptr_t)p + strlen(name) + 1, 4);
        } break;

        case FDT_END_NODE:
            depth--;
            if (depth < 0) {
                return;
            }
            p++;
            break;

        case FDT_PROP:
            p++;
            {
                struct fdt_property *prop = (struct fdt_property *)p;
                uint32_t len = fdt32_to_cpu(prop->len);
                p = (uint32_t *)ALIGN_UP(
                    (uintptr_t)p + sizeof(struct fdt_property) + len, 4);
            }
            break;

        case FDT_NOP:
            p++;
            break;

        case FDT_END:
            return;

        default:
            return;
        }
    }
}

static int fdt_match_compatible(const char **driver_compat,
                                const char *device_compat) {
    for (int i = 0; driver_compat[i] != NULL; i++) {
        if (strcmp(driver_compat[i], device_compat) == 0) {
            return i; // 返回匹配的索引
        }
    }
    return -1;
}

extern int fdt_driver_count;

static fdt_driver_t *fdt_find_driver(int node_offset,
                                     const char **matched_compat) {
    int len;
    const char *compatible = fdt_get_property(node_offset, "compatible", &len);

    if (!compatible || len <= 0) {
        return NULL;
    }

    /* compatible 可能包含多个以 null 分隔的字符串 */
    const char *compat_str = compatible;
    while (compat_str < compatible + len) {
        /* 遍历所有注册的驱动 */
        for (int i = 0; i < fdt_driver_count; i++) {
            if (fdt_match_compatible(fdt_drivers[i]->compatible, compat_str) >=
                0) {
                if (matched_compat) {
                    *matched_compat = compat_str;
                }
                return fdt_drivers[i];
            }
        }

        /* 移动到下一个 compatible 字符串 */
        compat_str += strlen(compat_str) + 1;
    }

    return NULL;
}

static void fdt_probe_node(const char *path, int offset, int depth) {
    const char *matched_compat = NULL;
    fdt_driver_t *driver = fdt_find_driver(offset, &matched_compat);

    if (!driver) {
        return; // 没有匹配的驱动
    }

    if (fdt_device_count >= MAX_FDT_DEVICES_NUM) {
        printk("FDT: Too many devices\n");
        return;
    }

    /* 创建设备实例 */
    fdt_device_t *dev = &fdt_devices[fdt_device_count];
    dev->name = path;
    dev->node_offset = offset;
    dev->fdt = g_fdt_ctx.dt_struct;
    dev->driver = driver;
    dev->driver_data = NULL;

    /* 调用驱动的 probe 函数 */
    printk("FDT: Probing device '%s' with driver '%s' (compatible: %s)\n", path,
           driver->name, matched_compat);

    if (driver->probe) {
        int ret = driver->probe(dev, matched_compat);
        if (ret == 0) {
            fdt_device_count++;
            printk("FDT: Device '%s' initialized successfully\n", path);
        } else {
            printk("FDT: Device '%s' probe failed: %d\n", path, ret);
        }
    } else {
        fdt_device_count++;
    }
}

void fdt_init() { fdt_walk_nodes(fdt_probe_node); }

#endif
