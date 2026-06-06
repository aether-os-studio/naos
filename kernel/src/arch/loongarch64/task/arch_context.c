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
    csr_write(LOONGARCH_CSR_EUEN,
              euen | LOONGARCH_EUEN_FPE | LOONGARCH_EUEN_SXE);
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

    asm volatile("vst $vr0,  %0, 0\n\t"
                 "vst $vr1,  %0, 16\n\t"
                 "vst $vr2,  %0, 32\n\t"
                 "vst $vr3,  %0, 48\n\t"
                 "vst $vr4,  %0, 64\n\t"
                 "vst $vr5,  %0, 80\n\t"
                 "vst $vr6,  %0, 96\n\t"
                 "vst $vr7,  %0, 112\n\t"
                 "vst $vr8,  %0, 128\n\t"
                 "vst $vr9,  %0, 144\n\t"
                 "vst $vr10, %0, 160\n\t"
                 "vst $vr11, %0, 176\n\t"
                 "vst $vr12, %0, 192\n\t"
                 "vst $vr13, %0, 208\n\t"
                 "vst $vr14, %0, 224\n\t"
                 "vst $vr15, %0, 240\n\t"
                 "vst $vr16, %0, 256\n\t"
                 "vst $vr17, %0, 272\n\t"
                 "vst $vr18, %0, 288\n\t"
                 "vst $vr19, %0, 304\n\t"
                 "vst $vr20, %0, 320\n\t"
                 "vst $vr21, %0, 336\n\t"
                 "vst $vr22, %0, 352\n\t"
                 "vst $vr23, %0, 368\n\t"
                 "vst $vr24, %0, 384\n\t"
                 "vst $vr25, %0, 400\n\t"
                 "vst $vr26, %0, 416\n\t"
                 "vst $vr27, %0, 432\n\t"
                 "vst $vr28, %0, 448\n\t"
                 "vst $vr29, %0, 464\n\t"
                 "vst $vr30, %0, 480\n\t"
                 "vst $vr31, %0, 496\n\t"
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

    asm volatile("vld $vr0,  %0, 0\n\t"
                 "vld $vr1,  %0, 16\n\t"
                 "vld $vr2,  %0, 32\n\t"
                 "vld $vr3,  %0, 48\n\t"
                 "vld $vr4,  %0, 64\n\t"
                 "vld $vr5,  %0, 80\n\t"
                 "vld $vr6,  %0, 96\n\t"
                 "vld $vr7,  %0, 112\n\t"
                 "vld $vr8,  %0, 128\n\t"
                 "vld $vr9,  %0, 144\n\t"
                 "vld $vr10, %0, 160\n\t"
                 "vld $vr11, %0, 176\n\t"
                 "vld $vr12, %0, 192\n\t"
                 "vld $vr13, %0, 208\n\t"
                 "vld $vr14, %0, 224\n\t"
                 "vld $vr15, %0, 240\n\t"
                 "vld $vr16, %0, 256\n\t"
                 "vld $vr17, %0, 272\n\t"
                 "vld $vr18, %0, 288\n\t"
                 "vld $vr19, %0, 304\n\t"
                 "vld $vr20, %0, 320\n\t"
                 "vld $vr21, %0, 336\n\t"
                 "vld $vr22, %0, 352\n\t"
                 "vld $vr23, %0, 368\n\t"
                 "vld $vr24, %0, 384\n\t"
                 "vld $vr25, %0, 400\n\t"
                 "vld $vr26, %0, 416\n\t"
                 "vld $vr27, %0, 432\n\t"
                 "vld $vr28, %0, 448\n\t"
                 "vld $vr29, %0, 464\n\t"
                 "vld $vr30, %0, 480\n\t"
                 "vld $vr31, %0, 496\n\t"
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
    dst->ctx->pc += 4;
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
