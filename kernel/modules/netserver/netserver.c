#include "netserver.h"

extern void real_socket_init();

__attribute__((visibility("default"))) int dlmain()
{
    real_socket_init();

    return 0;
}
