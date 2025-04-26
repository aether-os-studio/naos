#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

unsigned int getch()
{
    char buf[1];
    read(0, buf, 1);
    return (int)buf[0];
}

int vsprintf(char *buf, const char *fmt, va_list args);

char buf[4096];

int printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    int i = vsprintf(buf, fmt, args);

    va_end(args);

    write(1, (void *)buf, i);

    return i;
}

int sprintf(char *buf, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    int i = vsprintf(buf, fmt, args);

    va_end(args);

    return i;
}
