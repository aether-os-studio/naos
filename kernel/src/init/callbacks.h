#pragma once

#include <fs/vfs/vfs.h>
#include <dev/device.h>
#include <drivers/bus/bus.h>
#include <task/task.h>

typedef int (*on_new_task_t)(task_t *task);
typedef int (*on_exit_task_t)(task_t *task);
typedef int (*on_open_file_t)(task_t *task, int fd);
typedef int (*on_close_file_t)(task_t *task, int fd, fd_t *file);
typedef int (*on_new_device_t)(device_t *dev);
typedef int (*on_remove_device_t)(device_t *dev);
typedef int (*on_new_bus_device_t)(bus_device_t *dev);
typedef int (*on_remove_bus_device_t)(bus_device_t *dev);
typedef int (*on_sched_update_t)(void);
typedef int (*on_send_signal_t)(task_t *task, int sig, const siginfo_t *info);

typedef struct callback {
    void *fn;
    struct callback *next;
} callback_t;

void regist_on_new_task_callback(on_new_task_t fn);
void regist_on_exit_task_callback(on_exit_task_t fn);
void regist_on_open_file_callback(on_open_file_t fn);
void regist_on_close_file_callback(on_close_file_t fn);
void regist_on_new_device_callback(on_new_device_t fn);
void regist_on_remove_device_callback(on_remove_device_t fn);
void regist_on_new_bus_device_callback(on_new_bus_device_t fn);
void regist_on_remove_bus_device_callback(on_remove_bus_device_t fn);
void regist_on_sched_update_callback(on_sched_update_t fn);
void regist_on_send_signal_callback(on_send_signal_t fn);

void on_new_task_call(task_t *task);
void on_exit_task_call(task_t *task);
void on_open_file_call(task_t *task, int fd);
void on_close_file_call(task_t *task, int fd, fd_t *file);
void on_new_device_call(device_t *device);
void on_remove_device_call(device_t *device);
void on_new_bus_device_call(bus_device_t *device);
void on_remove_bus_device_call(bus_device_t *device);
void on_sched_update_call(void);
void on_send_signal_call(task_t *task, int sig, const siginfo_t *info);
