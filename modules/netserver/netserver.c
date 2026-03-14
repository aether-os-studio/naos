// Copyright (C) 2025-2026  lihanrui2913
#include "netserver.h"

extern void real_socket_v4_init();

__attribute__((visibility("default"))) int dlmain() {
    real_socket_v4_init();

    return 0;
}
