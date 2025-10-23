#include <task/task.h>
#include <task/eevdf.h>
#include "arch_context.h"
#include <mm/mm.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    memset(context, 0, sizeof(arch_context_t));
    context->mm = malloc(sizeof(task_mm_info_t));
    context->mm->page_table_addr = page_table_addr;
    context->mm->ref_count = 1;
    memset(&context->mm->task_vma_mgr, 0, sizeof(vma_manager_t));
    context->mm->task_vma_mgr.last_alloc_addr = USER_MMAP_START;
    context->mm->task_vma_mgr.initialized = false;
    context->mm->brk_start = USER_BRK_START;
    context->mm->brk_current = context->mm->brk_start;
    context->mm->brk_end = USER_BRK_END;
    context->ctx = (struct pt_regs *)stack - 1;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->ctx->ra = entry;
    context->ctx->epc = entry;
    context->ctx->sp = stack;
    context->ctx->a0 = initial_arg;
    context->dead = false;
    if (user_mode) {
        context->ctx->sstatus = (2UL << 32) | (1UL << 5);
    } else {
        context->ctx->sstatus = (2UL << 32) | (1UL << 5) | (1UL << 8);
    }
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {}

void arch_context_free(arch_context_t *context) {}

extern bool task_initialized;

task_t *arch_get_current() {
    if (task_initialized) {
        task_t *current;
        asm volatile("mv %0, tp\n\t" : "=r"(current));
        return current;
    } else
        return NULL;
}

void arch_set_current(task_t *current) {
    asm volatile("mv tp, %0\n\t" ::"r"(current));
}

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next,
                              uint64_t kernel_stack) {
    csr_write(sscratch, kernel_stack);

    uint64_t satp =
        MAKE_SATP_PADDR(SATP_MODE_SV48, 0, next->mm->page_table_addr);

    write_satp(satp);

    asm volatile("sfence.vma zero, zero\n\t");

    asm volatile("mv sp, %0\n\t"
                 "j ret_from_trap_handler\n\t" ::"r"(next->ctx));
}

extern void task_signal();

void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next) {
    prev->arch_context->ctx = ctx;

    if (prev == next) {
        return;
    }

    if (next->signal & SIGMASK(SIGKILL)) {
        return;
    }

    sched_update_itimer();
    sched_update_timerfd();

    task_signal();

    if (next->arch_context->dead)
        return;

    prev->current_state = prev->state;
    next->current_state = TASK_RUNNING;

    arch_set_current(next);

    arch_switch_with_context(prev->arch_context, next->arch_context,
                             next->kernel_stack);

    next->current_state = next->state;
    prev->current_state = TASK_RUNNING;
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {}

extern bool task_initialized;

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

void arch_yield() {
    if (task_initialized) {
        struct sched_entity *curr_se = current_task->sched_info;
        curr_se->is_yield = true;
        arch_enable_interrupt();
        sbi_set_timer(get_timer());
        arch_disable_interrupt();
    }
}

bool arch_check_elf(const Elf64_Ehdr *ehdr) {
    // 验证ELF魔数
    if (memcmp((void *)ehdr->e_ident,
               "\x7F"
               "ELF",
               4) != 0) {
        printk("Invalid ELF magic\n");
        return false;
    }

    // 检查架构和类型
    if (ehdr->e_ident[4] != 2 || // 64-bit
        ehdr->e_machine != 0xF3  // riscv64
    ) {
        printk("Unsupported ELF format\n");
        return false;
    }

    return true;
}
