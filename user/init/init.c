#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <aether/window.h>

int main()
{
    int pid = fork();
    if (pid == 0)
    {
        execve("/usr/bin/shell.exec", NULL, NULL);
        exit(-1);
    }
    else
    {
        int status;
        waitpid(pid, &status);
    }

    return 0;
}
