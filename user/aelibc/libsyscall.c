#include <libsyscall.h>

__attribute__((naked)) uint64_t enter_syscall(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t idx)
{
    __asm__ __volatile__(
        "movq %rcx, %r10\n\t"
        "movq %r9, %rax\n\t"
        "syscall\n\t"
        "ret\n\t");
}
