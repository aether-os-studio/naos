#include <arch/arch.h>

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM] = {NULL};

void syscall_handler_init() {
    memset(syscall_handlers, 0, sizeof(syscall_handlers));
}

void loongarch64_do_syscall(struct pt_regs *frame) { (void)frame; }
