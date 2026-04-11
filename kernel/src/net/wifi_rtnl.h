#pragma once

#include <net/rtnl.h>
#include <net/wifi.h>

int rtnl_wifi_attach(struct net_device *dev, wifi_device_t *wifi);
