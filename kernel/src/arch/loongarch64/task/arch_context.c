#include <arch/arch.h>
#include <arch/loongarch64/cpu_local.h>
#include <mm/mm.h>
#include <task/sched.h>
#include <task/task.h>

#ifndef EM_LOONGARCH
#define EM_LOONGARCH 258
#endif

extern void kernel_thread_func(void);
extern void ret_from_fork(void);
extern void loongarch64_trap_return(void);

static inline uint64_t loongarch64_fpu_enable_kernel(void) {
    uint64_t euen = csr_read(LOONGARCH_CSR_EUEN);
    csr_write(LOONGARCH_CSR_EUEN, euen | LOONGARCH_EUEN_FPE);
    return euen;
}

static inline void loongarch64_fpu_restore_kernel_state(uint64_t euen) {
    csr_write(LOONGARCH_CSR_EUEN, euen);
}

void loongarch64_fpu_state_init(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    memset(fpu_ctx, 0, sizeof(*fpu_ctx));
}

void loongarch64_fpu_save(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    uint64_t euen = loongarch64_fpu_enable_kernel();

    asm volatile("fst.d $f0,  %0, 0\n\t"
                 "fst.d $f1,  %0, 8\n\t"
                 "fst.d $f2,  %0, 16\n\t"
                 "fst.d $f3,  %0, 24\n\t"
                 "fst.d $f4,  %0, 32\n\t"
                 "fst.d $f5,  %0, 40\n\t"
                 "fst.d $f6,  %0, 48\n\t"
                 "fst.d $f7,  %0, 56\n\t"
                 "fst.d $f8,  %0, 64\n\t"
                 "fst.d $f9,  %0, 72\n\t"
                 "fst.d $f10, %0, 80\n\t"
                 "fst.d $f11, %0, 88\n\t"
                 "fst.d $f12, %0, 96\n\t"
                 "fst.d $f13, %0, 104\n\t"
                 "fst.d $f14, %0, 112\n\t"
                 "fst.d $f15, %0, 120\n\t"
                 "fst.d $f16, %0, 128\n\t"
                 "fst.d $f17, %0, 136\n\t"
                 "fst.d $f18, %0, 144\n\t"
                 "fst.d $f19, %0, 152\n\t"
                 "fst.d $f20, %0, 160\n\t"
                 "fst.d $f21, %0, 168\n\t"
                 "fst.d $f22, %0, 176\n\t"
                 "fst.d $f23, %0, 184\n\t"
                 "fst.d $f24, %0, 192\n\t"
                 "fst.d $f25, %0, 200\n\t"
                 "fst.d $f26, %0, 208\n\t"
                 "fst.d $f27, %0, 216\n\t"
                 "fst.d $f28, %0, 224\n\t"
                 "fst.d $f29, %0, 232\n\t"
                 "fst.d $f30, %0, 240\n\t"
                 "fst.d $f31, %0, 248\n\t"
                 :
                 : "r"(fpu_ctx)
                 : "memory");

    uint64_t fcc0, fcc1, fcc2, fcc3, fcc4, fcc5, fcc6, fcc7;
    asm volatile("movcf2gr %0, $fcc0\n\t"
                 "movcf2gr %1, $fcc1\n\t"
                 "movcf2gr %2, $fcc2\n\t"
                 "movcf2gr %3, $fcc3\n\t"
                 "movcf2gr %4, $fcc4\n\t"
                 "movcf2gr %5, $fcc5\n\t"
                 "movcf2gr %6, $fcc6\n\t"
                 "movcf2gr %7, $fcc7\n\t"
                 : "=r"(fcc0), "=r"(fcc1), "=r"(fcc2), "=r"(fcc3), "=r"(fcc4),
                   "=r"(fcc5), "=r"(fcc6), "=r"(fcc7));
    fpu_ctx->fcc = (fcc0 & 0xff) | ((fcc1 & 0xff) << 8) |
                   ((fcc2 & 0xff) << 16) | ((fcc3 & 0xff) << 24) |
                   ((fcc4 & 0xff) << 32) | ((fcc5 & 0xff) << 40) |
                   ((fcc6 & 0xff) << 48) | ((fcc7 & 0xff) << 56);

    uint64_t fcsr;
    asm volatile("movfcsr2gr %0, $fcsr0" : "=r"(fcsr));
    fpu_ctx->fcsr = (uint32_t)fcsr;

    loongarch64_fpu_restore_kernel_state(euen);
}

void loongarch64_fpu_restore(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    uint64_t euen = loongarch64_fpu_enable_kernel();

    asm volatile("fld.d $f0,  %0, 0\n\t"
                 "fld.d $f1,  %0, 8\n\t"
                 "fld.d $f2,  %0, 16\n\t"
                 "fld.d $f3,  %0, 24\n\t"
                 "fld.d $f4,  %0, 32\n\t"
                 "fld.d $f5,  %0, 40\n\t"
                 "fld.d $f6,  %0, 48\n\t"
                 "fld.d $f7,  %0, 56\n\t"
                 "fld.d $f8,  %0, 64\n\t"
                 "fld.d $f9,  %0, 72\n\t"
                 "fld.d $f10, %0, 80\n\t"
                 "fld.d $f11, %0, 88\n\t"
                 "fld.d $f12, %0, 96\n\t"
                 "fld.d $f13, %0, 104\n\t"
                 "fld.d $f14, %0, 112\n\t"
                 "fld.d $f15, %0, 120\n\t"
                 "fld.d $f16, %0, 128\n\t"
                 "fld.d $f17, %0, 136\n\t"
                 "fld.d $f18, %0, 144\n\t"
                 "fld.d $f19, %0, 152\n\t"
                 "fld.d $f20, %0, 160\n\t"
                 "fld.d $f21, %0, 168\n\t"
                 "fld.d $f22, %0, 176\n\t"
                 "fld.d $f23, %0, 184\n\t"
                 "fld.d $f24, %0, 192\n\t"
                 "fld.d $f25, %0, 200\n\t"
                 "fld.d $f26, %0, 208\n\t"
                 "fld.d $f27, %0, 216\n\t"
                 "fld.d $f28, %0, 224\n\t"
                 "fld.d $f29, %0, 232\n\t"
                 "fld.d $f30, %0, 240\n\t"
                 "fld.d $f31, %0, 248\n\t"
                 :
                 : "r"(fpu_ctx)
                 : "memory");

    uint64_t fcc = fpu_ctx->fcc;
    uint64_t fcc0 = (fcc >> 0) & 0xff;
    uint64_t fcc1 = (fcc >> 8) & 0xff;
    uint64_t fcc2 = (fcc >> 16) & 0xff;
    uint64_t fcc3 = (fcc >> 24) & 0xff;
    uint64_t fcc4 = (fcc >> 32) & 0xff;
    uint64_t fcc5 = (fcc >> 40) & 0xff;
    uint64_t fcc6 = (fcc >> 48) & 0xff;
    uint64_t fcc7 = (fcc >> 56) & 0xff;
    asm volatile("movgr2cf $fcc0, %0\n\t"
                 "movgr2cf $fcc1, %1\n\t"
                 "movgr2cf $fcc2, %2\n\t"
                 "movgr2cf $fcc3, %3\n\t"
                 "movgr2cf $fcc4, %4\n\t"
                 "movgr2cf $fcc5, %5\n\t"
                 "movgr2cf $fcc6, %6\n\t"
                 "movgr2cf $fcc7, %7\n\t"
                 :
                 : "r"(fcc0), "r"(fcc1), "r"(fcc2), "r"(fcc3), "r"(fcc4),
                   "r"(fcc5), "r"(fcc6), "r"(fcc7)
                 : "memory");

    uint64_t fcsr = fpu_ctx->fcsr;
    asm volatile("movgr2fcsr $fcsr0, %0" : : "r"(fcsr) : "memory");

    loongarch64_fpu_restore_kernel_state(euen);
}

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    memset(context, 0, sizeof(*context));
    context->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));
    loongarch64_fpu_state_init(context->fpu_ctx);
    context->page_table_addr = page_table_addr;
    context->ctx = (struct pt_regs *)stack - 1;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->sp = (uint64_t)context->ctx;
    context->kernel_interrupt_enabled = false;

    if (user_mode) {
        context->ra = (uint64_t)loongarch64_trap_return;
        context->ctx->pc = entry;
        context->ctx->sp = stack;
        context->ctx->usp = stack;
        context->ctx->csr_prmd = LOONGARCH_PRMD_USER;
        context->ctx->a0 = initial_arg;
        context->ctx->syscallno = NO_SYSCALL;
    } else {
        context->ra = (uint64_t)kernel_thread_func;
        context->s0 = entry;
        context->s1 = initial_arg;
        context->ctx->syscallno = NO_SYSCALL;
    }
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {
    (void)clone_flags;
    memset(dst, 0, sizeof(*dst));
    dst->page_table_addr = src->page_table_addr;
    dst->kernel_interrupt_enabled = src->kernel_interrupt_enabled;
    dst->ctx = (struct pt_regs *)stack - 1;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->a0 = 0;
    dst->ctx->syscallno = src->ctx ? src->ctx->syscallno : NO_SYSCALL;
    dst->ra = (uint64_t)ret_from_fork;
    dst->sp = (uint64_t)dst->ctx;
    dst->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));
    if (src->fpu_ctx) {
        if (current_task && current_task->arch_context == src)
            loongarch64_fpu_save(src->fpu_ctx);
        memcpy(dst->fpu_ctx, src->fpu_ctx, sizeof(fpu_context_t));
    } else {
        loongarch64_fpu_state_init(dst->fpu_ctx);
    }
}

void arch_context_free(arch_context_t *context) {
    if (!context)
        return;

    if (context->fpu_ctx) {
        free_frames_bytes(context->fpu_ctx, sizeof(fpu_context_t));
        context->fpu_ctx = NULL;
    }
}

void arch_context_save_interrupt_state(arch_context_t *context, bool enabled) {
    context->kernel_interrupt_enabled = enabled;
}

task_t *arch_get_current() {
    loongarch64_cpu_local_t *local = loongarch64_get_cpu_local();
    return local ? local->task_ptr : NULL;
}

void arch_set_current(task_t *current) {
    loongarch64_cpu_local_set_current(current);
}

void __switch_to(task_t *prev, task_t *next) {
    loongarch64_cpu_local_t *local = loongarch64_get_cpu_local();
    if (local) {
        local->task_ptr = next;
        local->syscall_stack = next ? next->syscall_stack : 0;
        local->kernel_stack = next ? next->kernel_stack : 0;
    }

    loongarch64_fpu_save(prev->arch_context->fpu_ctx);
    loongarch64_fpu_restore(next->arch_context->fpu_ctx);

    task_mark_on_cpu(prev, false);
    if (prev->state == TASK_DIED && task_is_reaped(prev))
        task_schedule_reap();
    task_mark_on_cpu(next, true);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {
    if (!context->fpu_ctx)
        context->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));

    context->ctx = (struct pt_regs *)current_task->kernel_stack - 1;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->ra = (uint64_t)loongarch64_trap_return;
    context->sp = (uint64_t)context->ctx;
    context->ctx->pc = entry;
    context->ctx->sp = stack;
    context->ctx->usp = stack;
    context->ctx->csr_prmd = LOONGARCH_PRMD_USER;
    context->ctx->syscallno = NO_SYSCALL;
    loongarch64_fpu_state_init(context->fpu_ctx);
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_disable_interrupt();
    arch_context_to_user_mode(context, entry, stack);
    loongarch64_set_user_page_table_root(current_task->mm->page_table_addr);
    loongarch64_fpu_restore(context->fpu_ctx);

    asm volatile("move $sp, %0\n\t"
                 "jr %1\n\t" ::"r"(context->ctx),
                 "r"(context->ra)
                 : "memory");
}

bool arch_check_elf(const Elf64_Ehdr *ehdr) {
    return ehdr && ehdr->e_machine == EM_LOONGARCH;
}
