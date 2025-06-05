#include <drivers/net/net.h>
#include <drivers/bus/msi.h>
#if defined(__x86_64__)
#include <drivers/net/rtl8139.h>
#endif

nic_controller_t nic_controller;

void net_init()
{
#if defined(__x86_64__)
    if (rtl8139_init())
    {
        return;
    }
#endif
}
