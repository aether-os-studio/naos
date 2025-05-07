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
        execv("/usr/bin/shell", NULL);
        exit(-1);
    }
    else
    {
        waitpid(pid, NULL, 0);
    }

    return 0;
}
