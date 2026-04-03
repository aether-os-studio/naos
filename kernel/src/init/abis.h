#pragma once

#include <mm/mm.h>
#include <task/task_struct.h>
#include <drivers/bus/bus.h>

typedef struct abi {
    void (*init)(void);
    void (*init_before_thread)(void);
    void (*init_after_thread)(void);
    void (*init_before_user)(void);
    void *(*regist_input_dev)(const char *device_name, void *arg);
    void (*input_generate_event)(void *item, uint16_t type, uint16_t code,
                                 int32_t value, uint64_t sec, uint64_t usecs);
} abi_t;

extern abi_t *system_abi;

void regist_system_abi(abi_t *abi);
void regist_syscall_handler(int num, syscall_handle_t handler);
