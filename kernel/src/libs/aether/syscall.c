#include <libs/aether/syscall.h>
#include <mod/dlinker.h>

extern syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM];

void regist_syscall_handler(uint64_t idx, syscall_handle_t handler) {
    syscall_handlers[idx] = handler;
}

EXPORT_SYMBOL(regist_syscall_handler);
