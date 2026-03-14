#include <arch/arch.h>
#include <task/task.h>
#include <fs/vfs/fcntl.h>
#include <libs/strerror.h>
#include <arch/loongarch64/syscall/nr.h>

void syscall_init() {}

// Beware the 65 character limit!
char sysname[] = "NeoAetherOS";
char nodename[] = "aether";
char release[] = BUILD_VERSION;
char version[] = BUILD_VERSION;
char machine[] = "x86_64";

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM];

void syscall_handler_init() { memset(syscall_handlers, 0, MAX_SYSCALL_NUM); }

spinlock_t syscall_debug_lock = SPIN_INIT;

void syscall_handler(struct pt_regs *regs, uint64_t user_regs) {}
