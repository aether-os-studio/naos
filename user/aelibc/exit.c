#include <libsyscall.h>

void exit(int code)
{
    enter_syscall(code, 0, 0, 0, 0, SYS_EXIT);
}

void abort()
{
    exit(-1);
}
