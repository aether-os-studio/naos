#include "arch_context.h"
#include <mm/mm.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/sched.h>

void kernel_thread_func();
asm("kernel_thread_func:\n\t"
    "    popq %r15\n\t"
    "    popq %r14\n\t"
    "    popq %r13\n\t"
    "    popq %r12\n\t"
    "    popq %r11\n\t"
    "    popq %r10\n\t"
    "    popq %r9\n\t"
    "    popq %r8\n\t"
    "    popq %rbx\n\t"
    "    popq %rcx\n\t"
    "    popq %rdx\n\t"
    "    popq %rsi\n\t"
    "    popq %rdi\n\t"
    "    popq %rbp\n\t"
    "    popq %rax\n\t"
    "    addq $0x38, %rsp\n\t"
    "    movq %rdx, %rdi\n\t"
    "    callq *%rbx\n\t"
    "    movq $0, %rdi\n\t"
    "    callq task_exit\n\t");

extern void ret_to_user();

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
    context->mm->task_vma_mgr.initialized = false;
    context->mm->brk_start = USER_BRK_START;
    context->mm->brk_current = context->mm->brk_start;
    context->mm->brk_end = USER_BRK_END;
    context->ctx = (struct pt_regs *)stack - 1;
    context->ctx->rsp = (uint64_t)context->ctx;
    context->ctx->rbp = (uint64_t)context->ctx;
    context->ctx->rflags = (1UL << 9);
    context->fsbase = 0;
    context->gsbase = 0;
    context->dead = false;
    if (user_mode) {
        context->rip = (uint64_t)kernel_thread_func;
        context->rsp = (uint64_t)context->ctx;
        context->ctx->rbx = entry;
        context->ctx->rdx = initial_arg;
        context->ctx->cs = SELECTOR_USER_CS;
        context->ctx->ss = SELECTOR_USER_DS;
    } else {
        context->rip = (uint64_t)ret_to_user;
        context->rsp = (uint64_t)context->ctx;
        context->ctx->rip = entry;
        context->ctx->rdi = initial_arg;
        context->ctx->cs = SELECTOR_KERNEL_CS;
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
    dst->ctx = (struct pt_regs *)stack - 1;
    dst->rip = (uint64_t)ret_to_user;
    dst->rsp = (uint64_t)dst->ctx;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
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

void __switch_to(task_t *prev, task_t *next) {
    prev->arch_context->fsbase = read_fsbase();
    prev->arch_context->gsbase = read_gsbase();

    if (prev->arch_context->fpu_ctx) {
        asm volatile("fxsave (%0)" ::"r"(prev->arch_context->fpu_ctx));
    }

    if (next->arch_context->fpu_ctx) {
        asm volatile("fxrstor (%0)" ::"r"(next->arch_context->fpu_ctx));
    }

    if (prev->arch_context->mm != next->arch_context->mm) {
        asm volatile(
            "movq %0, %%cr3" ::"r"(next->arch_context->mm->page_table_addr)
            : "memory");
    }

    tss[current_cpu_id].rsp0 = next->kernel_stack;

    write_fsbase(next->arch_context->fsbase);
    write_gsbase(next->arch_context->gsbase);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {
    context->ctx = (struct pt_regs *)current_task->kernel_stack - 1;

    context->rip = (uint64_t)ret_to_user;
    context->rsp = (uint64_t)context->ctx;

    memset(context->ctx, 0, sizeof(struct pt_regs));

    context->ctx->rip = entry;
    context->ctx->rsp = stack;
    context->ctx->rbp = stack;
    context->ctx->cs = SELECTOR_USER_CS;
    context->ctx->ss = SELECTOR_USER_DS;

    context->ctx->rflags = (1UL << 9);

    memset(context->fpu_ctx, 0, sizeof(fpu_context_t));
    context->fpu_ctx->mxscr = 0x1f80;
    context->fpu_ctx->fcw = 0x037f;
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_disable_interrupt();

    arch_context_to_user_mode(context, entry, stack);

    asm volatile("movq %0, %%cr3" ::"r"(context->mm->page_table_addr)
                 : "memory");

    asm volatile("movq %0, %%rsp\n\t"
                 "jmp ret_from_exception" ::"r"(context->ctx));
}

extern bool task_initialized;

void arch_yield() {
    if (task_initialized) {
        schedule(SCHED_FLAG_YIELD);
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
