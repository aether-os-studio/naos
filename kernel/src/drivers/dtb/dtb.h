#pragma once

#include <libs/klibc.h>

// DTB头部结构（参考设备树规范）
struct fdt_header
{
    uint32_t magic;             // 魔数 0xd00dfeed
    uint32_t totalsize;         // DTB总大小
    uint32_t off_dt_struct;     // 结构块偏移
    uint32_t off_dt_strings;    // 字符串块偏移
    uint32_t off_mem_rsvmap;    // 保留内存区偏移
    uint32_t version;           // 版本
    uint32_t last_comp_version; // 兼容版本
    uint32_t boot_cpuid_phys;   // 启动CPU物理ID
    uint32_t size_dt_strings;   // 字符串块大小
    uint32_t size_dt_struct;    // 结构块大小
};

// 设备树节点属性结构
struct fdt_property
{
    uint32_t tag;     // 属性标签（0x00000003）
    uint32_t len;     // 值长度
    uint32_t nameoff; // 属性名在字符串块的偏移
    // 值数据（按4字节对齐）
};

void dtb_init();
