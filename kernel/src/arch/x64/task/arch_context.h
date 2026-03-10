#pragma once
#pragma GCC optimize("O0")

#include <arch/x64/irq/ptrace.h>
#include <libs/elf.h>
#include <mm/mm.h>

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
    struct pt_regs *ctx;
    fpu_context_t *fpu_ctx;
    bool dead;
} arch_context_t;

#define switch_mm(prev, next)                                                  \
    do {                                                                       \
        asm volatile("movq %0, %%cr3" ::"r"(next->mm->page_table_addr)         \
                     : "memory");                                              \
    } while (0)

extern void arch_context_switch(task_t *prev, task_t *next,
                                arch_context_t *prev_ctx,
                                arch_context_t *next_ctx);

#define switch_to(prev, next)                                                  \
    do {                                                                       \
        arch_context_switch((prev), (next), (prev)->arch_context,              \
                            (next)->arch_context);                             \
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
