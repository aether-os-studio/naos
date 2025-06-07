#include <libs/klibc.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <mm/mm.h>
#include <fs/vfs/vfs.h>
#include <fs/partition.h>
#include <fs/termios.h>
#include <task/task.h>
#include <task/signal.h>
#include <net/socket.h>

#if defined(__x86_64__)
#include <drivers/bus/msi.h>
#endif
