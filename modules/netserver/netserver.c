// Copyright (C) 2025  lihanrui2913
#include "netserver.h"

extern void real_socket_init();
extern void real_socket_v6_init();

__attribute__((visibility("default"))) int dlmain() {
    real_socket_init();
    real_socket_v6_init();

    return 0;
}
