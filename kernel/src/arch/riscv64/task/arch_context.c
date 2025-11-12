#include <task/task.h>
#include <task/rrs.h>
#include "arch_context.h"
#include <mm/mm.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>

void kernel_thread_func();
asm("kernel_thread_func:\n\t"
    "    ld ra, 0(sp)\n\t" // 恢复 ra
    // sp 稍后恢复
    "    ld gp, 16(sp)\n\t"   // 恢复 gp
    "    ld tp, 24(sp)\n\t"   // 恢复 tp
    "    ld t0, 32(sp)\n\t"   // 恢复 t0
    "    ld t1, 40(sp)\n\t"   // 恢复 t1
    "    ld t2, 48(sp)\n\t"   // 恢复 t2
    "    ld s0, 56(sp)\n\t"   // 恢复 s0/fp
    "    ld s1, 64(sp)\n\t"   // 恢复 s1
    "    ld a0, 72(sp)\n\t"   // 恢复 a0
    "    ld a1, 80(sp)\n\t"   // 恢复 a1
    "    ld a2, 88(sp)\n\t"   // 恢复 a2
    "    ld a3, 96(sp)\n\t"   // 恢复 a3
    "    ld a4, 104(sp)\n\t"  // 恢复 a4
    "    ld a5, 112(sp)\n\t"  // 恢复 a5
    "    ld a6, 120(sp)\n\t"  // 恢复 a6
    "    ld a7, 128(sp)\n\t"  // 恢复 a7
    "    ld s2, 136(sp)\n\t"  // 恢复 s2
    "    ld s3, 144(sp)\n\t"  // 恢复 s3
    "    ld s4, 152(sp)\n\t"  // 恢复 s4
    "    ld s5, 160(sp)\n\t"  // 恢复 s5
    "    ld s6, 168(sp)\n\t"  // 恢复 s6
    "    ld s7, 176(sp)\n\t"  // 恢复 s7
    "    ld s8, 184(sp)\n\t"  // 恢复 s8
    "    ld s9, 192(sp)\n\t"  // 恢复 s9
    "    ld s10, 200(sp)\n\t" // 恢复 s10
    "    ld s11, 208(sp)\n\t" // 恢复 s11
    "    ld t3, 216(sp)\n\t"  // 恢复 t3
    "    ld t4, 224(sp)\n\t"  // 恢复 t4
    "    ld t5, 232(sp)\n\t"  // 恢复 t5
    "    ld t6, 240(sp)\n\t"  // 恢复 t6

    "    addi sp, sp, 296\n\t"
    // RISC-V: s1 存放函数指针（对应 rbx），a2 是参数（对应 rdx）
    "    mv a0, a2\n\t" // 将 a2 作为第一个参数传递
    "    jalr s1\n\t"   // 调用 s1 中的函数指针
    // 线程退出
    "    li a0, 0\n\t"      // 参数设为 0
    "    j task_exit\n\t"); // 调用 task_exit

extern void ret_from_trap_handler();

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
    context->fpu_ctx = alloc_frames_bytes(sizeof(fpu_context_t));
    memset(context->fpu_ctx, 0, sizeof(fpu_context_t));
    context->fpu_ctx->fcsr = FCSR_INIT_DEFAULT;
    context->dead = false;
    if (user_mode) {
        // context->ctx->sstatus = (2UL << 32) | (1UL << 18) | (3UL << 13) |
        // (1UL
        // << 5) | (1UL << 0); todo
    } else {
        context->ctx->sstatus = (2UL << 32) | (1UL << 18) | (3UL << 13) |
                                (1UL << 5) | (1UL << 0) | (1UL << 8);
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
        printk("src->mm == NULL!!! src = %#018lx", src);
    }
    dst->mm = clone_page_table(src->mm, clone_flags);
    if (!dst->mm) {
        printk("dst->mm == NULL!!! dst = %#018lx", dst);
    }
    dst->ctx = (struct pt_regs *)stack - 1;
    dst->ra = (uint64_t)ret_from_trap_handler;
    dst->sp = (uint64_t)dst->ctx;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->epc += 4;
    dst->ctx->a0 = 0;
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
    fpu_save_context(prev->arch_context->fpu_ctx);
    fpu_restore_context(next->arch_context->fpu_ctx);

    uint64_t satp = MAKE_SATP_PADDR(SATP_MODE_SV48, 0,
                                    next->arch_context->mm->page_table_addr);

    asm volatile("csrw satp, %0" : : "r"(satp) : "memory");
    asm volatile("sfence.vma" : : : "memory");

    csr_write(sscratch, next->kernel_stack);
}

extern void task_signal();

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
        schedule();
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
