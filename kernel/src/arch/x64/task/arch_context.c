#include "arch_context.h"
#include <mm/mm.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/eevdf.h>

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    memset(context, 0, sizeof(arch_context_t));

    if (!context->fpu_ctx) {
        context->fpu_ctx = alloc_frames_bytes(DEFAULT_PAGE_SIZE);
        memset(context->fpu_ctx, 0, DEFAULT_PAGE_SIZE);
        context->fpu_ctx->mxscr = 0x1f80;
        context->fpu_ctx->fcw = 0x037f;
    }
    context->mm = malloc(sizeof(task_mm_info_t));
    context->mm->page_table_addr = page_table_addr;
    context->mm->ref_count = 1;
    memset(&context->mm->task_vma_mgr, 0, sizeof(vma_manager_t));
    context->mm->task_vma_mgr.last_alloc_addr = USER_MMAP_START;
    context->mm->task_vma_mgr.initialized = false;
    context->mm->brk_start = USER_BRK_START;
    context->mm->brk_current = context->mm->brk_start;
    context->mm->brk_end = USER_BRK_END;
    context->ctx = (struct pt_regs *)(stack - 8) - 1;
    context->ctx->rip = entry;
    context->ctx->rsp = stack - 8;
    context->ctx->rbp = stack - 8;
    context->ctx->rflags = (0UL << 12) | (0b10) | (1UL << 9);
    context->ctx->rdi = initial_arg;
    context->fsbase = 0;
    context->gsbase = 0;
    context->dead = false;
    if (user_mode) {
        context->ctx->cs = SELECTOR_USER_CS;
        context->ctx->ds = SELECTOR_USER_DS;
        context->ctx->es = SELECTOR_USER_DS;
        context->ctx->ss = SELECTOR_USER_DS;
    } else {
        context->ctx->cs = SELECTOR_KERNEL_CS;
        context->ctx->ds = SELECTOR_KERNEL_DS;
        context->ctx->es = SELECTOR_KERNEL_DS;
        context->ctx->ss = SELECTOR_KERNEL_DS;
    }
}

extern void ret_from_syscall();

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {
    if (!src->mm) {
        printk("src->mm == NULL!!! src = %#018lx", src);
    }
    dst->mm = clone_page_table(src->mm, clone_flags);
    if (!dst->mm) {
        printk("dst->mm == NULL!!! dst = %#018lx", dst);
    }
    dst->ctx = (struct pt_regs *)(stack - 8) - 1;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->rcx = dst->ctx->rip;
    dst->ctx->r11 = dst->ctx->rflags;
    dst->ctx->rip = (uint64_t)ret_from_syscall;
    dst->ctx->cs = SELECTOR_KERNEL_CS;
    dst->ctx->ss = SELECTOR_KERNEL_DS;
    dst->ctx->ds = SELECTOR_KERNEL_DS;
    dst->ctx->es = SELECTOR_KERNEL_DS;
    dst->ctx->rsp = (uint64_t)dst->ctx;
    dst->ctx->rax = 0;
    dst->fpu_ctx = alloc_frames_bytes(DEFAULT_PAGE_SIZE);
    memset(dst->fpu_ctx, 0, DEFAULT_PAGE_SIZE);
    if (src->fpu_ctx) {
        memcpy(dst->fpu_ctx, src->fpu_ctx, DEFAULT_PAGE_SIZE);
        dst->fpu_ctx->mxscr = 0x1f80;
        dst->fpu_ctx->fcw = 0x037f;
    }
    dst->fsbase = src->fsbase;
    dst->gsbase = src->gsbase;
}

void arch_context_free(arch_context_t *context) {
    if (context->fpu_ctx) {
        free_frames_bytes(context->fpu_ctx, DEFAULT_PAGE_SIZE);
    }
    context->dead = true;
}

task_t *arch_get_current() { return (task_t *)read_kgsbase(); }

void arch_set_current(task_t *current) { write_kgsbase((uint64_t)current); }

extern tss_t tss[MAX_CPU_NUM];

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next,
                              uint64_t kernel_stack) {
    arch_disable_interrupt();

    if (prev) {
        prev->fsbase = read_fsbase();
        prev->gsbase = read_gsbase();

        if (prev->fpu_ctx && ((uint64_t)prev->fpu_ctx & 15) == 0) {
            asm volatile("fxsave (%0)" ::"r"(prev->fpu_ctx));
        }
    }

    // Start to switch
    if (next->fpu_ctx && ((uint64_t)next->fpu_ctx & 15) == 0) {
        asm volatile("fxrstor (%0)" ::"r"(next->fpu_ctx));
    }

    if (!prev || (prev->mm != next->mm)) {
        asm volatile("movq %0, %%cr3" ::"r"(next->mm->page_table_addr));
    }

    tss[current_cpu_id].rsp0 = kernel_stack - 8;

    write_fsbase(next->fsbase);
    write_gsbase(next->gsbase);

    asm volatile("movq %0, %%rsp\n\t"
                 "jmp ret_from_exception" ::"r"(next->ctx));
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
                               uint64_t stack) {
    context->ctx = (struct pt_regs *)(current_task->kernel_stack - 8) - 1;

    memset(context->ctx, 0, sizeof(struct pt_regs));

    context->ctx->rip = entry;
    context->ctx->rsp = stack;
    context->ctx->rbp = stack;
    context->ctx->cs = SELECTOR_USER_CS;
    context->ctx->ds = SELECTOR_USER_DS;
    context->ctx->es = SELECTOR_USER_DS;
    context->ctx->ss = SELECTOR_USER_DS;

    context->ctx->rflags = (0UL << 12) | (0b10) | (1UL << 9);
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_disable_interrupt();

    arch_context_to_user_mode(context, entry, stack);

    asm volatile("movq %0, %%cr3" ::"r"(context->mm->page_table_addr));

    asm volatile("movq %0, %%rsp\n\t"
                 "jmp ret_from_exception" ::"r"(context->ctx));
}

extern bool task_initialized;

void arch_yield() {
    if (task_initialized) {
        struct sched_entity *curr_se =
            (struct sched_entity *)current_task->sched_info;
        curr_se->is_yield = true;
        asm volatile(
            "sti\n\tint %0\n\tcli\n\t" ::"i"(APIC_TIMER_INTERRUPT_VECTOR));
    }
}

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

uint64_t sys_arch_prctl(uint64_t cmd, uint64_t arg) {
    switch (cmd) {
    case ARCH_SET_FS:
        current_task->arch_context->fsbase = arg;
        write_fsbase(current_task->arch_context->fsbase);
        return 0;
    case ARCH_SET_GS:
        current_task->arch_context->gsbase = arg;
        write_gsbase(current_task->arch_context->gsbase);
        return 0;
    case ARCH_GET_FS:
        return current_task->arch_context->fsbase;
    case ARCH_GET_GS:
        return current_task->arch_context->gsbase;
    default:
        return (uint64_t)(-ENOSYS);
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
        ehdr->e_machine != 0x3E  // x86_64
    ) {
        printk("Unsupported ELF format\n");
        return false;
    }

    return true;
}
