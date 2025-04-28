#include <sys/types.h>
#include <stdlib.h>

extern void heap_init();

extern int main(int argc, char **argv, char **envp);

void aelibc_start(int argc, char **argv, char **envp)
{
    heap_init();

    int ret = main(argc, argv, envp);

    exit(ret);
}
