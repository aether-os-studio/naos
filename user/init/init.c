#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

int main()
{
    printf("init process is running...\n");

    int pid = fork();
    if (pid == 0)
    {
        execve("/usr/bin/shell.exec", NULL, NULL);
        exit(-1);
    }
    else
    {
        waitpid(pid, NULL, 0);
    }

    return 0;
}
