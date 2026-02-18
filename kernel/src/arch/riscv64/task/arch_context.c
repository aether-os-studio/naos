#include <task/task.h>
#include <task/sched.h>
#include "arch_context.h"
#include <mm/mm.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>

extern void kernel_thread_func();

extern void ret_from_trap_handler();

#define SSTATUS_GET_FS(sstatus) (((sstatus) >> 13) & 0b11)
#define SSTATUS_SET_FS(sstatus, fs)                                            \
    ((sstatus) |= (((uint64_t)(fs) & 0b11) << 13))

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    memset(context, 0, sizeof(arch_context_t));
    context->mm = malloc(sizeof(task_mm_info_t));
    context->mm->page_table_addr = page_table_addr;
    context->mm->ref_count = 1;
    memset(&context->mm->task_vma_mgr, 0, sizeof(vma_manager_t));
    context->mm->task_vma_mgr.initialized = false;
    context->mm->brk_start = USER_BRK_START;
    context->mm->brk_current = context->mm->brk_start;
    context->mm->brk_end = USER_BRK_END;
    context->ctx = (struct pt_regs *)stack - 1;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));
    memset(context->fpu_ctx, 0, sizeof(fpu_context_t));
    context->fpu_ctx->fcsr = FCSR_INIT_DEFAULT;
    context->dead = false;
    if (user_mode) {
        context->ctx->sstatus =
            (2UL << 32) | (1UL << 18) | (1UL << 5) | (1UL << 0); // todo
    } else {
        context->ctx->sstatus =
            (2UL << 32) | (1UL << 18) | (1UL << 5) | (1UL << 0) | (1UL << 8);
        context->ra = (uint64_t)kernel_thread_func;
        context->sp = (uint64_t)context->ctx;
        context->ctx->s1 = entry;
        context->ctx->a2 = initial_arg;
        context->ctx->sp = (uint64_t)context->ctx;
    }
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {
    if (!src->mm) {
        printk("src->mm == NULL!!! src = %#018lx\n", src);
    }
    dst->mm = clone_page_table(src->mm, clone_flags);
    if (!dst->mm) {
        printk("dst->mm == NULL!!! dst = %#018lx\n", dst);
    }
    dst->ctx = (struct pt_regs *)stack - 1;
    dst->ra = (uint64_t)ret_from_trap_handler;
    dst->sp = (uint64_t)dst->ctx;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->epc += 4;
    dst->ctx->a0 = 0;
    dst->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));
    memset(dst->fpu_ctx, 0, sizeof(fpu_context_t));
    dst->fpu_ctx->fcsr = FCSR_INIT_DEFAULT;
}

void arch_context_free(arch_context_t *context) {
    free_frames_bytes(context->fpu_ctx, sizeof(fpu_context_t));
    context->dead = true;
}

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

void __switch_to(task_t *prev, task_t *next) {
    arch_disable_interrupt();

    if (prev->arch_context->ctx->sstatus & (1UL << 63)) {
        if (SSTATUS_GET_FS(prev->arch_context->ctx->sstatus) == 3) {
            fpu_save_context(prev->arch_context->fpu_ctx);
            SSTATUS_SET_FS(prev->arch_context->ctx->sstatus, 2);
        }
    }
    if (SSTATUS_GET_FS(next->arch_context->ctx->sstatus) != 0) {
        fpu_restore_context(next->arch_context->fpu_ctx);
        SSTATUS_SET_FS(next->arch_context->ctx->sstatus, 2);
    }

    uint64_t satp = MAKE_SATP_PADDR(SATP_MODE_SV48, 0,
                                    next->arch_context->mm->page_table_addr);

    asm volatile("csrw satp, %0" : : "r"(satp) : "memory");
    asm volatile("sfence.vma" : : : "memory");

    csr_write(sscratch, next->is_kernel ? 0 : next->kernel_stack);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {
    context->ctx = (struct pt_regs *)current_task->kernel_stack - 1;

    context->ra = (uint64_t)ret_from_trap_handler;
    context->sp = (uint64_t)context->ctx;

    memset(context->ctx, 0, sizeof(struct pt_regs));

    context->ctx->ktp = (uint64_t)current_task;
    context->ctx->tp = (uint64_t)current_task;
    context->ctx->gp = cpuid_to_hartid[current_cpu_id];

    context->ctx->epc = entry;
    context->ctx->sp = stack;
    context->ctx->sstatus =
        (2UL << 32) | (1UL << 18) | (3UL << 13) | (1UL << 5) | (1UL << 0);

    memset(context->fpu_ctx, 0, sizeof(fpu_context_t));
    context->fpu_ctx->fcsr = FCSR_INIT_DEFAULT;
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_context_to_user_mode(context, entry, stack);

    asm volatile("mv sp, %0\n\t"
                 "j ret_from_trap_handler\n\t" ::"r"(context->ctx));
}

extern bool task_initialized;

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];

extern bool task_initialized;

void arch_yield() {
    if (task_initialized) {
        schedule(SCHED_FLAG_YIELD);
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
