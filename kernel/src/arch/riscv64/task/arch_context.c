#include <task/task.h>
#include "arch_context.h"
#include <mm/mm.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    memset(context, 0, sizeof(arch_context_t));
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {}

void arch_context_free(arch_context_t *context) {}

task_t *arch_get_current() { return NULL; }

void arch_set_current(task_t *current) {}

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next,
                              uint64_t kernel_stack) {}

extern void task_signal();

void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next) {}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {}

void arch_yield() {}

bool arch_check_elf(const Elf64_Ehdr *ehdr) {
    // 验证ELF魔数
    if (memcmp((void *)ehdr->e_ident,
               "\x7F"
               "ELF",
               4) != 0) {
        printk("Invalid ELF magic\n");
        return false;
    }

    // // 检查架构和类型
    // if (ehdr->e_ident[4] != 2 || // 64-bit
    //     ehdr->e_machine != 0x3E  // x86_64
    // )
    // {
    //     printk("Unsupported ELF format\n");
    //     return false;
    // }

    return true;
}
