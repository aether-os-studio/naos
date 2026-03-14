#include <init/abis.h>

abi_t *system_abi;

void regist_system_abi(abi_t *abi) { system_abi = abi; }
void regist_syscall_handler(int num, syscall_handle_t handler) {
    syscall_handlers[num] = handler;
}
