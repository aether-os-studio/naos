#pragma once

#include <libs/klibc.h>
#include <libs/aether/mm.h>
#include <libs/aether/fs.h>
#include <libs/aether/task.h>

typedef uint32_t nfds_t;

struct pollfd
{
    int fd;
    short events;
    short revents;
};
