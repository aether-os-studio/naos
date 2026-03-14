#include <libs/klibc.h>

#define KB_QUEUE_SIZE 256

typedef struct {
    char tmp_buffer[KB_QUEUE_SIZE];
    uint16_t tmp_head;
    uint16_t tmp_tail;
    uint16_t tmp_count;
    char buffer[KB_QUEUE_SIZE];
    uint16_t head;
    uint16_t tail;
    uint16_t count;
} kb_queue_t;

kb_queue_t kb_queue = {{0}, 0, 0, 0, {0}, 0, 0, 0};

bool queue_push(char c) {
    if (kb_queue.tmp_count >= KB_QUEUE_SIZE) {
        return false;
    }
    kb_queue.tmp_buffer[kb_queue.tmp_tail] = c;
    kb_queue.tmp_tail = (kb_queue.tmp_tail + 1) % KB_QUEUE_SIZE;
    kb_queue.tmp_count++;
    return true;
}

bool queue_pop_tmp(char *c) {
    if (kb_queue.tmp_count == 0) {
        return false;
    }
    *c = kb_queue.tmp_buffer[kb_queue.tmp_head];
    kb_queue.tmp_head = (kb_queue.tmp_head + 1) % KB_QUEUE_SIZE;
    kb_queue.tmp_count--;
    return true;
}

bool queue_pop(char *c) {
    if (kb_queue.count == 0) {
        return false;
    }
    *c = kb_queue.buffer[kb_queue.head];
    kb_queue.head = (kb_queue.head + 1) % KB_QUEUE_SIZE;
    kb_queue.count--;
    return true;
}

bool queue_flush() {
    if (kb_queue.tmp_count == 0) {
        return false;
    }

    int i = 0;
    while (kb_queue.tmp_count > 0) {
        queue_pop_tmp(&kb_queue.buffer[kb_queue.tail]);
        kb_queue.tail = (kb_queue.tail + 1) % KB_QUEUE_SIZE;
        if (kb_queue.count < KB_QUEUE_SIZE) {
            kb_queue.count++;
        } else {
            kb_queue.head = (kb_queue.head + 1) % KB_QUEUE_SIZE;
        }
        i++;
    }

    (void)i;

    return true;
}

void queue_push_string(const char *str) {
    while (*str) {
        if (!queue_push(*str++)) {
            break;
        }
    }
    queue_flush();
}

int kb_available() { return kb_queue.count; }

void kb_clear() {
    kb_queue.head = 0;
    kb_queue.tail = 0;
    kb_queue.count = 0;
}

int kb_read(char *buffer, int n) {
    int i;
    for (i = 0; i < n; i++) {
        if (!queue_pop(&buffer[i])) {
            break;
        }
    }
    return i;
}
