#pragma once

#include <mm/mm.h>
#include <task/task_struct.h>
#include <dev/device.h>

struct fd;
typedef struct fd fd_t;

typedef struct abi {
    void (*init)(void);
    void (*init_before_thread)(void);
    void (*init_after_thread)(void);
    void (*init_before_user)(void);
    int (*on_sched_update)(void);
    int (*on_send_signal)(task_t *task, int sig, int code);
    int (*run_user_init)(const char *path);
    int (*on_new_task)(task_t *task);
    int (*on_exit_task)(task_t *task);
    int (*on_open_file)(task_t *task, int fd);
    int (*on_close_file)(task_t *task, int fd, fd_t *file);
    int (*on_new_device)(device_t *dev);
    int (*on_remove_device)(device_t *dev);
    void *(*regist_input_dev)(const char *device_name, void *arg);
    void (*handle_kb_scancode)(uint8_t scan_code, bool pressed,
                               bool is_extended);
    void (*handle_mouse_event)(uint8_t flag, int8_t x, int8_t y, int8_t z);
} abi_t;

extern abi_t *system_abi;

void regist_system_abi(abi_t *abi);
void regist_syscall_handler(int num, syscall_handle_t handler);
