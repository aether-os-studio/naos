#include <arch/aarch64/task/arch_context.h>
#include <arch/aarch64/cpu_local.h>
#include <mm/mm.h>
#include <task/task.h>
#include <task/sched.h>

extern void kernel_thread_func();
extern void arch_context_switch_exit();

void aarch64_fpu_state_init(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    memset(fpu_ctx, 0, sizeof(*fpu_ctx));
}

void aarch64_fpu_save(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    asm volatile("stp q0, q1, [%0, #0]\n\t"
                 "stp q2, q3, [%0, #32]\n\t"
                 "stp q4, q5, [%0, #64]\n\t"
                 "stp q6, q7, [%0, #96]\n\t"
                 "stp q8, q9, [%0, #128]\n\t"
                 "stp q10, q11, [%0, #160]\n\t"
                 "stp q12, q13, [%0, #192]\n\t"
                 "stp q14, q15, [%0, #224]\n\t"
                 "stp q16, q17, [%0, #256]\n\t"
                 "stp q18, q19, [%0, #288]\n\t"
                 "stp q20, q21, [%0, #320]\n\t"
                 "stp q22, q23, [%0, #352]\n\t"
                 "stp q24, q25, [%0, #384]\n\t"
                 "stp q26, q27, [%0, #416]\n\t"
                 "stp q28, q29, [%0, #448]\n\t"
                 "stp q30, q31, [%0, #480]\n\t"
                 "mrs x1, fpcr\n\t"
                 "str x1, [%0, #512]\n\t"
                 "mrs x1, fpsr\n\t"
                 "str x1, [%0, #520]\n\t"
                 :
                 : "r"(fpu_ctx)
                 : "memory", "x1");
}

void aarch64_fpu_restore(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    asm volatile("ldp q0, q1, [%0, #0]\n\t"
                 "ldp q2, q3, [%0, #32]\n\t"
                 "ldp q4, q5, [%0, #64]\n\t"
                 "ldp q6, q7, [%0, #96]\n\t"
                 "ldp q8, q9, [%0, #128]\n\t"
                 "ldp q10, q11, [%0, #160]\n\t"
                 "ldp q12, q13, [%0, #192]\n\t"
                 "ldp q14, q15, [%0, #224]\n\t"
                 "ldp q16, q17, [%0, #256]\n\t"
                 "ldp q18, q19, [%0, #288]\n\t"
                 "ldp q20, q21, [%0, #320]\n\t"
                 "ldp q22, q23, [%0, #352]\n\t"
                 "ldp q24, q25, [%0, #384]\n\t"
                 "ldp q26, q27, [%0, #416]\n\t"
                 "ldp q28, q29, [%0, #448]\n\t"
                 "ldp q30, q31, [%0, #480]\n\t"
                 "ldr x1, [%0, #512]\n\t"
                 "msr fpcr, x1\n\t"
                 "ldr x1, [%0, #520]\n\t"
                 "msr fpsr, x1\n\t"
                 :
                 : "r"(fpu_ctx)
                 : "memory", "x1");
}

static inline uint64_t aarch64_read_tpidr_el0(void) {
    uint64_t value;
    asm volatile("mrs %0, TPIDR_EL0" : "=r"(value));
    return value;
}

static inline void aarch64_write_tpidr_el0(uint64_t value) {
    asm volatile("msr TPIDR_EL0, %0" : : "r"(value));
}

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    if (!context->fpu_ctx) {
        context->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));
        aarch64_fpu_state_init(context->fpu_ctx);
    }

    context->ctx = (struct pt_regs *)stack - 1;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->tpidr_el0 = 0;

    uint32_t spsr = 0;
    if (user_mode) {
        context->pc = (uint64_t)arch_context_switch_exit;
        context->sp = (uint64_t)context->ctx;
        context->ctx->pc = entry;
        context->ctx->sp_el0 = stack;
        context->ctx->x0 = initial_arg;
        spsr = 0x80000300;
    } else {
        context->pc = (uint64_t)kernel_thread_func;
        context->sp = (uint64_t)context->ctx;
        context->ctx->x19 = entry;
        context->ctx->x20 = initial_arg;
        spsr = 0x80000305;
    }

    context->ctx->cpsr = spsr;

    context->usermode = user_mode;
}

extern void ret_from_fork();

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {
    dst->usermode = src->usermode;
    if (!src->tpidr_el0)
        src->tpidr_el0 = aarch64_read_tpidr_el0();
    dst->tpidr_el0 = src->tpidr_el0;
    dst->ctx = (struct pt_regs *)stack - 1;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->x0 = 0;
    dst->pc = (uint64_t)ret_from_fork;
    dst->sp = (uint64_t)dst->ctx;

    dst->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));
    if (src->fpu_ctx) {
        if (current_task && current_task->arch_context == src) {
            aarch64_fpu_save(src->fpu_ctx);
        }
        memcpy(dst->fpu_ctx, src->fpu_ctx, sizeof(fpu_context_t));
    } else {
        aarch64_fpu_state_init(dst->fpu_ctx);
    }
}

void arch_context_free(arch_context_t *context) {
    if (context->fpu_ctx) {
        free_frames_bytes(context->fpu_ctx, sizeof(fpu_context_t));
        context->fpu_ctx = NULL;
    }
}

extern bool task_initialized;

task_t *arch_get_current() {
    if (task_initialized) {
        aarch64_cpu_local_t *local = aarch64_get_cpu_local();
        return local ? local->task_ptr : NULL;
    }
    return NULL;
}

void arch_set_current(task_t *current) {
    aarch64_cpu_local_set_current(current);
}

void __switch_to(task_t *prev, task_t *next) {
    prev->arch_context->tpidr_el0 = aarch64_read_tpidr_el0();
    aarch64_fpu_save(prev->arch_context->fpu_ctx);

    aarch64_write_tpidr_el0(next->arch_context->tpidr_el0);
    aarch64_fpu_restore(next->arch_context->fpu_ctx);

    task_mark_on_cpu(prev, false);
    if (prev->state == TASK_DIED && task_is_reaped(prev))
        task_schedule_reap();
    task_mark_on_cpu(next, true);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {
    if (!context->fpu_ctx) {
        context->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));
    }

    context->ctx = (struct pt_regs *)current_task->kernel_stack - 1;
    context->tpidr_el0 = 0;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->usermode = true;
    context->pc = (uint64_t)arch_context_switch_exit;
    context->sp = (uint64_t)context->ctx;
    context->ctx->pc = entry;
    context->ctx->sp_el0 = stack;
    context->ctx->cpsr = 0x80000300;
    aarch64_fpu_state_init(context->fpu_ctx);
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_disable_interrupt();

    arch_context_to_user_mode(context, entry, stack);
    aarch64_write_tpidr_el0(context->tpidr_el0);
    aarch64_fpu_restore(context->fpu_ctx);

    arch_flush_tlb_all();

    asm volatile("mov sp, %0\n\t"
                 "b arch_context_switch_exit\n\t" ::"r"(context->ctx));
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
        ehdr->e_machine != 0xB7  // aarch64
    ) {
        printk("Unsupported ELF format\n");
        return false;
    }

    return true;
}
