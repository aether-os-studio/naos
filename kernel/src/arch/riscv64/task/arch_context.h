#pragma once

#include <arch/riscv64/irq/ptrace.h>
#include <libs/elf.h>
#include <mm/mm.h>

#define USER_STACK_START 0x00006fffff000000
#define USER_STACK_END 0x0000700000000000

struct task;
typedef struct task task_t;

typedef struct arch_context {
    uint64_t ra;
    uint64_t sp;
    struct pt_regs *ctx;
    task_mm_info_t *mm;
    bool dead;
} arch_context_t;

typedef struct arch_signal_frame {
} __attribute__((packed)) arch_signal_frame_t;

#define switch_to(prev, next)                                                  \
    do {                                                                       \
        asm volatile("addi sp, sp, -16\n\t" /* 分配栈空间 */                   \
                     "sd s0, 0(sp)\n\t"     /* 保存帧指针 */                   \
                     "sd t0, 8(sp)\n\t"     /* 保存临时寄存器 */               \
                     "sd sp, %0\n\t"        /* 保存当前sp */                   \
                     "ld sp, %2\n\t"        /* 加载next的sp */                 \
                     "la t0, 1f\n\t"        /* 获取返回地址 */                 \
                     "sd t0, %1\n\t"        /* 保存到prev->ra */               \
                     "ld t0, %3\n\t"        /* 加载next的ra */                 \
                     "mv ra, t0\n\t"        /* 压入返回地址 */                 \
                     "mv a0, %4\n\t"        /* 第一个参数 prev */              \
                     "mv a1, %5\n\t"        /* 第二个参数 next */              \
                     "j __switch_to\n\t"    /* 跳转到__switch_to */            \
                     "1:\n\t"               /* 返回点 */                       \
                     "ld t0, 8(sp)\n\t"     /* 恢复t0 */                       \
                     "ld s0, 0(sp)\n\t"     /* 恢复s0 */                       \
                     "addi sp, sp, 16\n\t"  /* 恢复栈指针 */                   \
                     : "=m"(prev->arch_context->sp),                           \
                       "=m"(prev->arch_context->ra)                            \
                     : "m"(next->arch_context->sp),                            \
                       "m"(next->arch_context->ra), "r"(prev), "r"(next)       \
                     : "memory", "t0", "a0", "a1");                            \
    } while (0)

void arch_context_init(arch_context_t *context, uint64_t page_table_dir,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg);
void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags);
void arch_context_free(arch_context_t *context);
task_t *arch_get_current();
void arch_set_current(task_t *current);

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next,
                              uint64_t kernel_stack);
void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next);
void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack);
void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack);

void arch_yield();

bool arch_check_elf(const Elf64_Ehdr *elf);
