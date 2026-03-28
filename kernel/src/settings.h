#pragma once

#define SERIAL_DEBUG 1
#define DEFAULT_TTY "ttyS0"

#define LIMINE_API_REVISION 3

#define PAGE_SIZE 4096UL

#define MAX_CPU_NUM 128
#define MAX_WORKER_NUM MAX_CPU_NUM
#define MAX_IO_CPU_NUM 8
#define STACK_SIZE (256 * 1024)

#define BUILD_VERSION "0.10.0"

#define MAX_TASK_NUM 16384

#if defined(__x86_64__)
#define SCHED_HZ 1000
#else
#define SCHED_HZ 250
#endif
