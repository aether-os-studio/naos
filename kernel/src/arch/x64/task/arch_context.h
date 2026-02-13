#pragma once

#include <arch/x64/irq/ptrace.h>
#include <libs/elf.h>
#include <mm/mm.h>

#define USER_STACK_START 0x00006ffffff00000
#define USER_STACK_END 0x0000700000000000

struct task;
typedef struct task task_t;

typedef struct fpu_context {
    uint16_t fcw;
    uint16_t fsw;
    uint16_t ftw;
    uint16_t fop;
    uint64_t word2;
    uint64_t word3;
    uint32_t mxscr;
    uint32_t mxcsr_mask;
    uint64_t mm[16];
    uint64_t xmm[32];
    uint64_t rest[12];
} fpu_context_t;

typedef struct sigaltstack {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
} stack_t;

typedef uint64_t gregset_t[23];

typedef struct {
    gregset_t gregs;
    fpu_context_t *fpregs;
    uint64_t __reserved1[8];
} mcontext_t;

typedef struct __ucontext {
    uint64_t uc_flags;
    struct __ucontext *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    uint64_t uc_sigmask;
    uint64_t __fpregs_mem[64];
} ucontext_t;

typedef struct arch_context {
    uint64_t rip;
    uint64_t rsp;
    uint64_t fsbase;
    uint64_t gsbase;
    task_mm_info_t *mm;
    struct pt_regs *ctx;
    fpu_context_t *fpu_ctx;
    bool dead;
} arch_context_t;

#define switch_to(prev, next)                                                  \
    do {                                                                       \
        asm volatile("pushq %%r15\n\t"                                         \
                     "pushq %%r14\n\t"                                         \
                     "pushq %%r13\n\t"                                         \
                     "pushq %%r12\n\t"                                         \
                     "pushq %%rbx\n\t"                                         \
                     "pushq %%rbp\n\t"                                         \
                     "movq %%rsp, %0\n\t"                                      \
                     "movq %2, %%rsp\n\t"                                      \
                     "leaq 1f(%%rip), %%rax\n\t"                               \
                     "movq %%rax, %1\n\t"                                      \
                     "movq %4, %%rdi\n\t"                                      \
                     "movq %5, %%rsi\n\t"                                      \
                     "pushq %3\n\t"                                            \
                     "jmp __switch_to\n\t"                                     \
                     "1:\n\t"                                                  \
                     "popq %%rbp\n\t"                                          \
                     "popq %%rbx\n\t"                                          \
                     "popq %%r12\n\t"                                          \
                     "popq %%r13\n\t"                                          \
                     "popq %%r14\n\t"                                          \
                     "popq %%r15\n\t"                                          \
                     : "=m"(prev->arch_context->rsp),                          \
                       "=m"(prev->arch_context->rip)                           \
                     : "m"(next->arch_context->rsp),                           \
                       "m"(next->arch_context->rip), "m"(prev), "m"(next)      \
                     : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",   \
                       "r11", "cc");                                           \
    } while (0)

void arch_context_init(arch_context_t *context, uint64_t page_table_dir,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg);
void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags);
void arch_context_free(arch_context_t *context);
task_t *arch_get_current();
void arch_set_current(task_t *current);

void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next);
void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack);
void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack);

uint64_t sys_arch_prctl(uint64_t cmd, uint64_t arg);

bool arch_check_elf(const Elf64_Ehdr *elf);
