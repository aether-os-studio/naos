#include "arch_context.h"
#include <mm/mm.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/sched.h>

extern void kernel_thread_func();

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
    context->ctx = (struct pt_regs *)stack - 1;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->ctx->rsp = (uint64_t)context->ctx;
    context->ctx->rbp = (uint64_t)context->ctx;
    context->ctx->rflags = (1UL << 9);
    context->fsbase = 0;
    context->gsbase = 0;
    context->dead = false;
    if (user_mode) {
        context->rip = (uint64_t)ret_to_user;
        context->rsp = (uint64_t)context->ctx;
        context->ctx->rip = entry;
        context->ctx->rdi = initial_arg;
        context->ctx->cs = SELECTOR_USER_CS;
        context->ctx->ss = SELECTOR_USER_DS;
    } else {
        context->rip = (uint64_t)kernel_thread_func;
        context->rsp = (uint64_t)context->ctx;
        context->ctx->rbx = entry;
        context->ctx->rdx = initial_arg;
        context->ctx->cs = SELECTOR_KERNEL_CS;
        context->ctx->ss = SELECTOR_KERNEL_DS;
    }
}

extern int write_task_user_memory(task_t *task, uint64_t uaddr, const void *src,
                                  size_t size);

extern void ret_from_fork();

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {
    (void)clone_flags;

    arch_flush_tlb_all();
    dst->ctx = (struct pt_regs *)stack - 1;
    dst->rip = (uint64_t)ret_from_fork;
    dst->rsp = (uint64_t)dst->ctx;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->rax = 0;

    dst->fpu_ctx = alloc_frames_bytes(DEFAULT_PAGE_SIZE);
    memset(dst->fpu_ctx, 0, DEFAULT_PAGE_SIZE);
    if (src->fpu_ctx) {
        memcpy(dst->fpu_ctx, src->fpu_ctx, DEFAULT_PAGE_SIZE);
    } else {
        dst->fpu_ctx->mxscr = 0x1f80;
        dst->fpu_ctx->fcw = 0x037f;
    }

    dst->fsbase = src->fsbase;
    dst->gsbase = src->gsbase;
    dst->dead = false;
}

void arch_context_free(arch_context_t *context) {
    if (context->fpu_ctx) {
        free_frames_bytes(context->fpu_ctx, DEFAULT_PAGE_SIZE);
    }
    context->dead = true;
}

task_t *arch_get_current() {
    task_t *task = NULL;
    if (x64_get_cpu_local()) {
        asm volatile("movq %%gs:0x10, %0" : "=r"(task));
    }
    return task;
}

void arch_set_current(task_t *current) { x64_cpu_local_set_current(current); }

extern tss_t tss[MAX_CPU_NUM];

void __switch_to(task_t *prev, task_t *next) {
    prev->arch_context->fsbase = read_fsbase();
    // prev->arch_context->gsbase = read_gsbase();

    if (prev->arch_context->fpu_ctx) {
        asm volatile("fxsave (%0)" ::"r"(prev->arch_context->fpu_ctx));
    }

    tss[current_cpu_id].rsp0 = next->kernel_stack;

    if (next->arch_context->fpu_ctx) {
        asm volatile("fxrstor (%0)" ::"r"(next->arch_context->fpu_ctx));
    }

    write_fsbase(next->arch_context->fsbase);
    // write_gsbase(next->arch_context->gsbase);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {
    context->ctx = (struct pt_regs *)current_task->kernel_stack - 1;

    context->rip = (uint64_t)ret_to_user;
    context->rsp = (uint64_t)context->ctx;

    memset(context->ctx, 0, sizeof(struct pt_regs));

    context->ctx->rip = entry;
    context->ctx->rsp = stack;
    context->ctx->cs = SELECTOR_USER_CS;
    context->ctx->ss = SELECTOR_USER_DS;

    context->ctx->rflags = (1UL << 9);

    context->fsbase = 0;
    context->gsbase = 0;

    memset(context->fpu_ctx, 0, sizeof(fpu_context_t));
    context->fpu_ctx->mxscr = 0x1f80;
    context->fpu_ctx->fcw = 0x037f;
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_disable_interrupt();

    arch_context_to_user_mode(context, entry, stack);

    context->fsbase = 0;
    write_fsbase(context->fsbase);
    // write_gsbase(context->gsbase);

    const uint16_t default_fcw = 0b1100111111;
    asm volatile("fldcw %0" : : "m"(default_fcw) : "memory");
    const uint32_t default_mxcsr = 0b1111110000000;
    asm volatile("ldmxcsr %0" : : "m"(default_mxcsr) : "memory");

    asm volatile("movq %0, %%rsp\n\t"
                 "jmp *%1" ::"r"(context->ctx),
                 "r"(context->rip));
}

extern bool task_initialized;

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

static inline bool is_canonical_user_addr(uint64_t addr) {
    return addr < (1ULL << 47);
}

uint64_t sys_arch_prctl(uint64_t cmd, uint64_t arg) {
    uint64_t value = 0;

    switch (cmd) {
    case ARCH_SET_FS:
        if (!is_canonical_user_addr(arg))
            return (uint64_t)(-EINVAL);
        current_task->arch_context->fsbase = arg;
        write_fsbase(current_task->arch_context->fsbase);
        return 0;
    case ARCH_SET_GS:
        if (!is_canonical_user_addr(arg))
            return (uint64_t)(-EINVAL);
        current_task->arch_context->gsbase = arg;
        // write_gsbase(current_task->arch_context->gsbase);
        return 0;
    case ARCH_GET_FS:
        value = current_task->arch_context->fsbase;
        if (copy_to_user((void *)arg, &value, sizeof(value)))
            return (uint64_t)(-EFAULT);
        return 0;
    case ARCH_GET_GS:
        value = current_task->arch_context->gsbase;
        if (copy_to_user((void *)arg, &value, sizeof(value)))
            return (uint64_t)(-EFAULT);
        return 0;
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
