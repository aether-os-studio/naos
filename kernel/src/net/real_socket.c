#include <net/real_socket.h>

real_socket_socket_t *real_sockets[MAX_SOCKETS_NUM];
spinlock_t real_sockets_lock = {0};
int socket_num = 0;

void regist_socket(int domain,
                   int (*socket)(int domain, int type, int protocol)) {
    spin_lock(&real_sockets_lock);
    real_sockets[socket_num] = malloc(sizeof(real_socket_socket_t));
    real_sockets[socket_num]->domain = domain;
    real_sockets[socket_num]->socket = socket;
    socket_num++;
    spin_unlock(&real_sockets_lock);
}
