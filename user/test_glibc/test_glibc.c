#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main()
{
    printf("Hello from glibc!!!\n");

    int pid = fork();
    if (pid == 0)
    {
        printf("Hello from child!!!\n");
    }
    else
    {
        printf("Hello from parent!!!\n");
    }
}
