#include <drivers/net/nic.h>

extern void e1000_init();
extern void virtio_net_init();

void net_init()
{
    e1000_init();

    virtio_net_init();
}