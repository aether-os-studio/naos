#pragma once

#define LIMINE_API_REVISION 3

#if defined(__loongarch__)
#define DEFAULT_PAGE_SIZE 16384UL
#else
#define DEFAULT_PAGE_SIZE 4096UL
#endif

#define MAX_CPU_NUM 256
#define STACK_SIZE 65536UL

#define BUILD_VERSION "0.69.2"

#define MAX_CONTINUE_NULL_TASKS 5
