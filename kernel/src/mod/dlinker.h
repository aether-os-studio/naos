#pragma once

#include <libs/klibc.h>
#include <mod/module.h>
#include <libs/elf.h>

#define KERNEL_MODULES_SPACE_START 0xffffffffd0000000
#define KERNEL_MODULES_SPACE_END 0xfffffffff0000000

typedef int (*dlinit_t)(void);

typedef struct {
    char *name;
    void *addr;
} dlfunc_t;

typedef struct module_symbol {
    char *module_name;
    char *name;
    uint64_t addr;
    uint64_t size;
    uint8_t type;
    bool exported;
} module_symbol_t;

typedef struct symbol_lookup_result {
    const char *name;
    const char *module_name;
    uint64_t symbol_addr;
    uint64_t symbol_size;
    uint64_t offset;
    bool is_module;
    bool exact_match;
} symbol_lookup_result_t;

/**
 * 加载一个内核模块
 * @param module 文件句柄
 */
bool dlinker_load(module_t *module);

dlfunc_t *find_func(const char *name);

bool dlinker_lookup_symbol_by_addr(uint64_t addr,
                                   symbol_lookup_result_t *result);

void find_kernel_symbol();

void dlinker_init();
