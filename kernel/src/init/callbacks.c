#include <init/callbacks.h>
#include <mm/mm.h>

spinlock_t callbacks_lock = SPIN_INIT;
callback_t *callbacks_new_task_head = NULL;
callback_t *callbacks_exit_task_head = NULL;
callback_t *callbacks_on_open_file_head = NULL;
callback_t *callbacks_on_close_file_head = NULL;
callback_t *callbacks_on_new_device_head = NULL;
callback_t *callbacks_on_remove_device_head = NULL;
callback_t *callbacks_on_sched_update_head = NULL;
callback_t *callbacks_on_send_signal_head = NULL;

callback_t *callback_new(void *fn) {
    callback_t *cb = malloc(sizeof(callback_t));
    cb->fn = fn;
    cb->next = NULL;
    return cb;
}

void callback_insert(callback_t **head, callback_t *cb) {
    if (!cb)
        return;
    spin_lock(&callbacks_lock);
    if (!*head)
        *head = cb;
    else {
        callback_t *prev = *head;
        while (prev->next) {
            prev = prev->next;
        }
        prev->next = cb;
    }
    spin_unlock(&callbacks_lock);
}

void regist_on_new_task_callback(on_new_task_t fn) {
    callback_insert(&callbacks_new_task_head, callback_new(fn));
}

void regist_on_exit_task_callback(on_exit_task_t fn) {
    callback_insert(&callbacks_exit_task_head, callback_new(fn));
}

void regist_on_open_file_callback(on_open_file_t fn) {
    callback_insert(&callbacks_on_open_file_head, callback_new(fn));
}

void regist_on_close_file_callback(on_close_file_t fn) {
    callback_insert(&callbacks_on_close_file_head, callback_new(fn));
}

void regist_on_new_device_callback(on_new_device_t fn) {
    callback_insert(&callbacks_on_new_device_head, callback_new(fn));
}

void regist_on_remove_device_callback(on_remove_device_t fn) {
    callback_insert(&callbacks_on_remove_device_head, callback_new(fn));
}

void regist_on_sched_update_callback(on_sched_update_t fn) {
    callback_insert(&callbacks_on_sched_update_head, callback_new(fn));
}

void regist_on_send_signal_callback(on_send_signal_t fn) {
    callback_insert(&callbacks_on_send_signal_head, callback_new(fn));
}

void on_new_task_call(task_t *task) {
    callback_t *ptr = callbacks_new_task_head;
    while (ptr) {
        on_new_task_t fn = ptr->fn;
        fn(task);
        ptr = ptr->next;
    }
}
void on_exit_task_call(task_t *task) {
    callback_t *ptr = callbacks_exit_task_head;
    while (ptr) {
        on_exit_task_t fn = ptr->fn;
        fn(task);
        ptr = ptr->next;
    }
}

void on_open_file_call(task_t *task, int fd) {
    callback_t *ptr = callbacks_on_open_file_head;
    while (ptr) {
        on_open_file_t fn = ptr->fn;
        fn(task, fd);
        ptr = ptr->next;
    }
}
void on_close_file_call(task_t *task, int fd, fd_t *file) {
    callback_t *ptr = callbacks_on_close_file_head;
    while (ptr) {
        on_close_file_t fn = ptr->fn;
        fn(task, fd, file);
        ptr = ptr->next;
    }
}

void on_new_device_call(device_t *device) {
    callback_t *ptr = callbacks_on_new_device_head;
    while (ptr) {
        on_new_device_t fn = ptr->fn;
        fn(device);
        ptr = ptr->next;
    }
}

void on_remove_device_call(device_t *device) {
    callback_t *ptr = callbacks_on_remove_device_head;
    while (ptr) {
        on_remove_device_t fn = ptr->fn;
        fn(device);
        ptr = ptr->next;
    }
}

void on_sched_update_call(void) {
    callback_t *ptr = callbacks_on_sched_update_head;
    while (ptr) {
        on_sched_update_t fn = ptr->fn;
        fn();
        ptr = ptr->next;
    }
}

void on_send_signal_call(task_t *task, int sig, const siginfo_t *info) {
    callback_t *ptr = callbacks_on_send_signal_head;
    while (ptr) {
        on_send_signal_t fn = ptr->fn;
        fn(task, sig, info);
        ptr = ptr->next;
    }
}
