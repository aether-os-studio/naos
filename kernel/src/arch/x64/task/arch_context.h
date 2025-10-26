#pragma once

#include <arch/x64/irq/ptrace.h>
#include <libs/elf.h>
#include <mm/mm.h>

#define USER_STACK_START 0x00006fffff800000
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
} __attribute__((aligned(16))) fpu_context_t;

struct fpstate {
    uint16_t cwd;
    uint16_t swd;
    uint16_t twd; /* Note this is not the same as the 32bit/x87/FSAVE twd */
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    uint32_t st_space[32];  /* 8*16 bytes for each FP-reg */
    uint32_t xmm_space[64]; /* 16*16 bytes for each XMM-reg  */
    uint32_t reserved2[24];
} __attribute__((packed));

typedef struct arch_context {
    uint64_t fsbase;
    uint64_t gsbase;
    task_mm_info_t *mm;
    struct pt_regs *ctx;
    fpu_context_t *fpu_ctx;
    bool dead;
} arch_context_t;

typedef struct arch_signal_frame {
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rsp;
    uint64_t rip;
    uint64_t eflags; /* RFLAGS */
    uint16_t cs;
    uint16_t gs;
    uint16_t fs;
    uint16_t ss; /* __pad0 */
    uint64_t err;
    uint64_t trapno;
    uint64_t oldmask;
    uint64_t cr2;
    struct fpstate *fpstate; /* zero when no FPU context */
    uint64_t reserved[8];
} __attribute__((packed)) arch_signal_frame_t;

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
uint64_t sys_arch_prctl(uint64_t cmd, uint64_t arg);

bool arch_check_elf(const Elf64_Ehdr *elf);
