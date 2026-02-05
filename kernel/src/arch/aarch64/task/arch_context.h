#pragma once

#include <libs/klibc.h>
#include <mm/mm.h>
#include <arch/aarch64/irq/ptrace.h>
#include <libs/elf.h>

#define __sysop_encode(op1, crn, crm, op2)                                     \
    "#" #op1 ",C" #crn ",C" #crm ",#" #op2

#define tlbi_alle1 __sysop_encode(4, 8, 7, 4)
#define tlbi_aside1 __sysop_encode(0, 8, 7, 2)
#define tlbi_rvaae1 __sysop_encode(0, 8, 6, 3)
#define tlbi_rvae1 __sysop_encode(0, 8, 6, 1)
#define tlbi_vaae1 __sysop_encode(0, 8, 7, 3)
#define tlbi_vae1 __sysop_encode(0, 8, 7, 1)

#define sys_a0(op) asm volatile("sys " op)

typedef struct arch_context {
    struct pt_regs *ctx;
    uint64_t pc;
    uint64_t sp;
    task_mm_info_t *mm;
    bool usermode;
    bool dead;
} arch_context_t;

typedef struct fpu_context {

} fpu_context_t;

#define switch_to(prev, next)                                                  \
    do {                                                                       \
        asm volatile("stp x29, x30, [sp, #-16]!\n\t" /* 保存 fp 和 lr */       \
                     "mov x9, sp\n\t"                /* 保存当前栈指针 */      \
                     "str x9, %0\n\t"                /* 保存到 prev->sp */     \
                     "adr x9, 1f\n\t"                /* 获取返回地址 */        \
                     "str x9, %1\n\t"                /* 保存到 prev->pc */     \
                     "ldr x9, %2\n\t"                /* 加载 next->sp */       \
                     "mov sp, x9\n\t"                /* 切换栈指针 */          \
                     "mov x0, %4\n\t"                /* 第一个参数 prev */     \
                     "mov x1, %5\n\t"                /* 第二个参数 next */     \
                     "ldr x30, %3\n\t"               /* 加载 next->pc 到 lr */ \
                     "b __switch_to\n\t"             /* 跳转到 __switch_to */  \
                     "1:\n\t"                        /* 返回点 */              \
                     "ldp x29, x30, [sp], #16\n\t"   /* 恢复 fp 和 lr */       \
                     : "=m"(prev->arch_context->sp),                           \
                       "=m"(prev->arch_context->pc)                            \
                     : "m"(next->arch_context->sp),                            \
                       "m"(next->arch_context->pc), "r"(prev), "r"(next)       \
                     : "memory", "x0", "x1", "x9");                            \
    } while (0)

typedef struct arch_signal_frame {
    uint64_t x30;
    uint64_t x28;
    uint64_t x29;
    uint64_t x26;
    uint64_t x27;
    uint64_t x24;
    uint64_t x25;
    uint64_t x22;
    uint64_t x23;
    uint64_t x20;
    uint64_t x21;
    uint64_t x18;
    uint64_t x19;
    uint64_t x16;
    uint64_t x17;
    uint64_t x14;
    uint64_t x15;
    uint64_t x12;
    uint64_t x13;
    uint64_t x10;
    uint64_t x11;
    uint64_t x8;
    uint64_t x9;
    uint64_t x6;
    uint64_t x7;
    uint64_t x4;
    uint64_t x5;
    uint64_t x2;
    uint64_t x3;
    uint64_t x0;
    uint64_t x1;
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint64_t signal;
    uint64_t code;
    uint64_t errno;
} arch_signal_frame_t;

#define USER_STACK_START 0x00006ffffff00000
#define USER_STACK_END 0x0000700000000000

struct task;
typedef struct task task_t;

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
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
