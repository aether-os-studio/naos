#include <stdio.h>
#include <unistd.h>

int main()
{
    printf("Hello world!!!\n");

    int pid = fork();
    if (pid == 0)
    {
        printf("is child process\n");
    }
    else
    {
        printf("is parent process\n");
    }
}
