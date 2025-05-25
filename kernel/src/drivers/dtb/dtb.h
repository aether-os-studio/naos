#pragma once

#include <libs/klibc.h>

#define FDT_BEGIN_NODE 0x00000001 // 节点开始标记
#define FDT_END_NODE 0x00000002   // 节点结束标记
#define FDT_PROP 0x00000003       // 属性标记
#define FDT_NOP 0x00000004        // 无操作标记
#define FDT_END 0x00000009        // 设备树结束标记

struct fdt_header
{
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};

struct fdt_property
{
    uint32_t tag;
    uint32_t len;
    uint32_t nameoff;
};

typedef struct
{
    const char *name;
    const void *properties;
    const void *dtb;
} dtb_node_t;

void dtb_init();
