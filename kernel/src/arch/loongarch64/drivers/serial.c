#include <arch/arch.h>

int init_serial()
{
    return 0;
}

char read_serial()
{
    return 0;
}

void write_serial(char a)
{
}

void serial_printk(char *buf, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (buf[i] == '\n')
            write_serial('\r');
        write_serial(buf[i]);
    }
}
