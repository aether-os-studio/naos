#include <sys/types.h>
#include <stdlib.h>

extern void init_heap();

extern int main(int argc, char **argv, char **envp);

void aelibc_start(int argc, char **argv, char **envp)
{
    init_heap();

    exit(main(argc, argv, envp));
}
