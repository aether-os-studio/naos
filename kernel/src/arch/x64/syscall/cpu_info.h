#pragma once

#include <libs/klibc.h>

struct cpu_info {
    int processor;
    char vendor_id[16];
    int cpu_family;
    int model;
    char model_name[64];
    int stepping;
    int microcode;
    int cpu_mhz;
    int cache_size;
    int physical_id;
    int siblings;
    int core_id;
    int cpu_cores;
    int apicid;
    int initial_apicid;
    bool fpu;
    bool fpu_exception;
    int cpuid_level;
    bool wp;
    char flags[512];
    char bugs[256];
    int bogomips;
    int clflush_size;
    int cache_alignment;
    char address_sizes[32];
    char power_management[64];
};

static inline void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                         uint32_t *ecx, uint32_t *edx) {
    asm volatile("cpuid"
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                 : "a"(leaf), "c"(0));
}

static inline void cpuid_count(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                               uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    asm volatile("cpuid"
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                 : "a"(leaf), "c"(subleaf));
}

static inline void cleanup_cpu_name(const char *raw_name, char *clean_name,
                                    size_t buffer_size) {
    const char *src = raw_name;
    char *dst = clean_name;
    size_t remaining = buffer_size - 1; // 为null terminator预留空间
    bool in_space_sequence = false;

    // 跳过前导空格
    while (*src == ' ' || *src == '\t') {
        src++;
    }

    // 复制并规范化空格
    while (*src && remaining > 0) {
        if (*src == ' ' || *src == '\t') {
            if (!in_space_sequence) {
                *dst++ = ' ';
                remaining--;
                in_space_sequence = true;
            }
        } else {
            *dst++ = *src;
            remaining--;
            in_space_sequence = false;
        }
        src++;
    }

    // 移除尾随空格
    while (dst > clean_name && *(dst - 1) == ' ') {
        dst--;
    }

    *dst = '\0';
}

// 获取CPU型号名称
static inline bool get_cpu_model_name(char *model_name, size_t buffer_size) {
    uint32_t eax, ebx, ecx, edx;
    char raw_name[49]; // 48字节 + null terminator

    if (!model_name || buffer_size == 0) {
        return false;
    }

    // 检查是否支持扩展CPUID功能
    cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
    if (eax < 0x80000004) {
        // 不支持处理器名称字符串
        if (buffer_size > 7) {
            strcpy(model_name, "Unknown");
        }
        return false;
    }

    // 获取处理器名称字符串 (48字节，分3次获取)
    char *p = raw_name;

    // CPUID 0x80000002: 获取前16字节
    cpuid(0x80000002, &eax, &ebx, &ecx, &edx);
    memcpy(p, &eax, 4);
    p += 4;
    memcpy(p, &ebx, 4);
    p += 4;
    memcpy(p, &ecx, 4);
    p += 4;
    memcpy(p, &edx, 4);
    p += 4;

    // CPUID 0x80000003: 获取中间16字节
    cpuid(0x80000003, &eax, &ebx, &ecx, &edx);
    memcpy(p, &eax, 4);
    p += 4;
    memcpy(p, &ebx, 4);
    p += 4;
    memcpy(p, &ecx, 4);
    p += 4;
    memcpy(p, &edx, 4);
    p += 4;

    // CPUID 0x80000004: 获取后16字节
    cpuid(0x80000004, &eax, &ebx, &ecx, &edx);
    memcpy(p, &eax, 4);
    p += 4;
    memcpy(p, &ebx, 4);
    p += 4;
    memcpy(p, &ecx, 4);
    p += 4;
    memcpy(p, &edx, 4);
    p += 4;

    // 确保字符串以null结尾
    raw_name[48] = '\0';

    // 清理字符串格式
    cleanup_cpu_name(raw_name, model_name, buffer_size);

    return true;
}

void parse_cpu_flags(char *flags_buffer, size_t buffer_size);

static inline void detect_cpu_info(struct cpu_info *info, int cpu_id) {
    uint32_t eax, ebx, ecx, edx;

    info->processor = cpu_id;

    // CPUID 0: 获取厂商ID
    cpuid(0, &eax, &ebx, &ecx, &edx);
    info->cpuid_level = eax;
    memcpy(info->vendor_id, &ebx, 4);
    memcpy(info->vendor_id + 4, &edx, 4);
    memcpy(info->vendor_id + 8, &ecx, 4);
    info->vendor_id[12] = '\0';

    // CPUID 1: 基本功能信息
    cpuid(1, &eax, &ebx, &ecx, &edx);
    info->cpu_family = (eax >> 8) & 0xf;
    info->model = (eax >> 4) & 0xf;
    info->stepping = eax & 0xf;

    // 扩展family和model
    if (info->cpu_family == 0xf) {
        info->cpu_family += (eax >> 20) & 0xff;
    }
    if (info->cpu_family >= 0x6) {
        info->model += ((eax >> 16) & 0xf) << 4;
    }

    info->apicid = (ebx >> 24) & 0xff;
    info->clflush_size = ((ebx >> 8) & 0xff) * 8;

    // 功能标志
    parse_cpu_flags(info->flags, sizeof(info->flags));

    // CPUID 0x80000000: 扩展功能
    cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
    if (eax >= 0x80000004) {
        // 获取处理器名称
        get_cpu_model_name(info->model_name, sizeof(info->model_name));
    }

    // 获取缓存信息
    info->cache_size = 0;
    info->cache_alignment = 16;

    // 获取频率信息
    info->cpu_mhz = 1000;

    // 计算BogoMIPS
    info->bogomips = 0;
}

char *generate_cpuinfo_buffer_dynamic(void);
