#include <drivers/net/nic.h>

extern void virtio_net_init();

void net_init()
{
    virtio_net_init();
}