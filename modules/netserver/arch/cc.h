#pragma once

#include <libs/klibc.h>
#include <boot/boot.h>
#include <mm/mm.h>
#include <fs/vfs/vfs.h>
#include <task/task.h>

typedef uint32_t nfds_t;

struct pollfd {
    int fd;
    short events;
    short revents;
};
