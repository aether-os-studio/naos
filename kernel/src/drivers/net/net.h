#pragma once

#include <libs/klibc.h>
#include <drivers/bus/pci.h>

void net_init();

typedef struct nic_controller
{
    enum
    {
        RTL8139
    } type;
    void *inner;
} nic_controller_t;
