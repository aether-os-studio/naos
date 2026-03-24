#include "arch_context.h"
#include <mm/mm.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/sched.h>

static uint64_t x64_fpu_state_bytes = sizeof(fpu_context_t);
static uint64_t x64_fpu_xsave_mask = 0;
static bool x64_fpu_use_xsave = false;

uint64_t x64_fpu_state_size(void) { return x64_fpu_state_bytes; }

bool x64_fpu_xsave_enabled(void) { return x64_fpu_use_xsave; }

void x64_fpu_configure_xsave(bool enabled, uint64_t xsave_mask,
                             uint64_t state_bytes) {
    x64_fpu_use_xsave = enabled;
    x64_fpu_xsave_mask = enabled ? xsave_mask : 0;
    x64_fpu_state_bytes = state_bytes ? state_bytes : sizeof(fpu_context_t);
}

void x64_fpu_state_init(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    memset(fpu_ctx, 0, x64_fpu_state_bytes);
    fpu_ctx->mxcsr = 0x1f80;
    fpu_ctx->cwd = 0x037f;

    if (x64_fpu_use_xsave && x64_fpu_state_bytes > X64_XSAVE_HDR_OFFSET) {
        x64_xsave_header_t *hdr =
            (x64_xsave_header_t *)((uint8_t *)fpu_ctx + X64_XSAVE_HDR_OFFSET);
        hdr->xstate_bv = x64_fpu_xsave_mask;
    }
}

void x64_fpu_save(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    if (x64_fpu_use_xsave) {
        uint32_t eax = (uint32_t)x64_fpu_xsave_mask;
        uint32_t edx = (uint32_t)(x64_fpu_xsave_mask >> 32);

        asm volatile("xsave (%0)"
                     :
                     : "r"(fpu_ctx), "a"(eax), "d"(edx)
                     : "memory");
        return;
    }

    asm volatile("fxsave (%0)" : : "r"(fpu_ctx) : "memory");
}

void x64_fpu_restore(fpu_context_t *fpu_ctx) {
    if (!fpu_ctx)
        return;

    if (x64_fpu_use_xsave) {
        uint32_t eax = (uint32_t)x64_fpu_xsave_mask;
        uint32_t edx = (uint32_t)(x64_fpu_xsave_mask >> 32);

        asm volatile("xrstor (%0)"
                     :
                     : "r"(fpu_ctx), "a"(eax), "d"(edx)
                     : "memory");
        return;
    }

    asm volatile("fxrstor (%0)" : : "r"(fpu_ctx) : "memory");
}

extern void kernel_thread_func();

extern void ret_to_user();

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    memset(context, 0, sizeof(arch_context_t));

    if (!context->fpu_ctx) {
        context->fpu_ctx = alloc_frames_bytes(x64_fpu_state_size());
        x64_fpu_state_init(context->fpu_ctx);
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

    dst->fpu_ctx = alloc_frames_bytes(x64_fpu_state_size());
    if (src->fpu_ctx) {
        memcpy(dst->fpu_ctx, src->fpu_ctx, x64_fpu_state_size());
    } else {
        x64_fpu_state_init(dst->fpu_ctx);
    }

    dst->fsbase = src->fsbase;
    dst->gsbase = src->gsbase;
    dst->dead = false;
}

void arch_context_free(arch_context_t *context) {
    if (context->fpu_ctx) {
        free_frames_bytes(context->fpu_ctx, x64_fpu_state_size());
    }
    context->dead = true;
}

task_t *arch_get_current() {
    x64_cpu_local_t *local = x64_get_cpu_local();
    return local ? local->task_ptr : NULL;
}

void arch_set_current(task_t *current) { x64_cpu_local_set_current(current); }

extern tss_t tss[MAX_CPU_NUM];

void __switch_to(task_t *prev, task_t *next) {
    prev->arch_context->fsbase = read_fsbase();
    prev->arch_context->gsbase = read_gsbase();

    x64_fpu_save(prev->arch_context->fpu_ctx);

    tss[current_cpu_id].rsp0 = next->kernel_stack;

    x64_fpu_restore(next->arch_context->fpu_ctx);

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
    context->ctx->cs = SELECTOR_USER_CS;
    context->ctx->ss = SELECTOR_USER_DS;

    context->ctx->rflags = (1UL << 9);

    context->fsbase = 0;
    context->gsbase = 0;

    x64_fpu_state_init(context->fpu_ctx);
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_disable_interrupt();

    arch_context_to_user_mode(context, entry, stack);

    context->fsbase = 0;
    write_fsbase(context->fsbase);
    write_gsbase(context->gsbase);

    x64_fpu_restore(context->fpu_ctx);

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
        write_gsbase(current_task->arch_context->gsbase);
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
