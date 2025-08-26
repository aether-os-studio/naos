#include <net/netdev.h>
#include <mm/mm.h>

netdev_t *netdevs[MAX_NETDEV_NUM] = {NULL};

void regist_netdev(void *desc, uint8_t *mac, uint32_t mtu, netdev_send_t send, netdev_recv_t recv)
{
    for (int i = 0; i < MAX_NETDEV_NUM; i++)
    {
        if (netdevs[i] == NULL)
        {
            netdevs[i] = malloc(sizeof(netdev_t));
            netdevs[i]->desc = desc;
            netdevs[i]->mtu = mtu;
            memcpy(netdevs[i]->mac, mac, sizeof(netdevs[i]->mac));
            netdevs[i]->send = send;
            netdevs[i]->recv = recv;
            break;
        }
    }
}

netdev_t *get_default_netdev()
{
    return netdevs[0];
}

int netdev_send(netdev_t *dev, void *data, uint32_t len)
{
    int ret = dev->send(dev->desc, data, len);
    return ret;
}

int netdev_recv(netdev_t *dev, void *data, uint32_t len)
{
    int ret = dev->recv(dev->desc, data, len);
    return ret;
}
