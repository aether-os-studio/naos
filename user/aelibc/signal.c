#include <libsyscall.h>

int ssetmask(int mask)
{
    return enter_syscall(mask, 0, 0, 0, 0, SYS_SETMASK);
}

extern void restorer();

int signal(int sig, uint64_t handler)
{
    return enter_syscall(sig, handler, (uint64_t)restorer, 0, 0, SYS_SIGNAL);
}
