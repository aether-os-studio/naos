#pragma once

#include <libs/klibc.h>
#include <mod/module.h>
#include <libs/elf.h>

#define KERNEL_MODULES_SPACE_START 0xffffb00000000000
#define KERNEL_MODULES_SPACE_END 0xffffc00000000000

typedef int (*dlinit_t)(void);

typedef struct {
    char *name;
    void *addr;
} dlfunc_t;

typedef struct module_symbol {
    char *name;
    uint64_t addr;
} module_symbol_t;

/**
 * 加载一个内核模块
 * @param module 文件句柄
 */
bool dlinker_load(module_t *module);

dlfunc_t *find_func(const char *name);

void find_kernel_symbol();

void dlinker_init();
