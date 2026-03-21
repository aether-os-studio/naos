#pragma once

#include <arch/x64/irq/ptrace.h>
#include <libs/elf.h>
#include <mm/mm.h>
#include <task/task_struct.h>

struct task;
typedef struct task task_t;

typedef struct x64_fpx_sw_bytes {
    uint32_t magic1;
    uint32_t extended_size;
    uint64_t xstate_bv;
    uint32_t xstate_size;
    uint32_t reserved1[7];
} x64_fpx_sw_bytes_t;

typedef struct fpu_context {
    uint16_t cwd;
    uint16_t swd;
    uint16_t twd;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcr_mask;
    uint32_t st_space[32];
    uint32_t xmm_space[64];
    uint32_t reserved2[12];
    union {
        uint32_t reserved3[12];
        x64_fpx_sw_bytes_t sw_reserved;
    };
} fpu_context_t;

typedef struct x64_xsave_header {
    uint64_t xstate_bv;
    uint64_t reserved1[2];
    uint64_t reserved2[5];
} x64_xsave_header_t;

#define X64_UC_FP_XSTATE 0x1
#define X64_FP_XSTATE_MAGIC1 0x46505853U
#define X64_FP_XSTATE_MAGIC2 0x46505845U
#define X64_FP_XSTATE_MAGIC2_SIZE sizeof(uint32_t)
#define X64_FPU_FRAME_ALIGN 64
#define X64_XSAVE_HDR_OFFSET 512

_Static_assert(sizeof(fpu_context_t) == 512,
               "x86_64 fpu_context_t must match Linux _fpstate size");
_Static_assert(offsetof(fpu_context_t, sw_reserved) == 464,
               "x86_64 sw_reserved layout must match Linux _fpstate");

typedef uint64_t gregset_t[23];

typedef struct {
    gregset_t gregs;
    fpu_context_t *fpregs;
    uint64_t __reserved1[8];
} mcontext_t;

typedef struct {
    uint64_t __bits[16];
} user_sigset_t;

typedef struct __ucontext {
    uint64_t uc_flags;
    struct __ucontext *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    user_sigset_t uc_sigmask;
    fpu_context_t __fpregs_mem;
    uint64_t __ssp[4];
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

#define X64_XSTATE_X87 (1ULL << 0)
#define X64_XSTATE_SSE (1ULL << 1)
#define X64_XSTATE_AVX (1ULL << 2)

uint64_t x64_fpu_state_size(void);
bool x64_fpu_xsave_enabled(void);
void x64_fpu_configure_xsave(bool enabled, uint64_t xsave_mask,
                             uint64_t state_bytes);
void x64_fpu_state_init(fpu_context_t *fpu_ctx);
void x64_fpu_save(fpu_context_t *fpu_ctx);
void x64_fpu_restore(fpu_context_t *fpu_ctx);

#define switch_mm(prev, next)                                                  \
    do {                                                                       \
        asm volatile("movq %0, %%cr3" ::"r"((next)->mm->page_table_addr)       \
                     : "memory");                                              \
    } while (0)

#define switch_to(prev, next)                                                  \
    do {                                                                       \
        asm volatile(                                                          \
            "pushq %%rax\n\t"                                                  \
            "pushq %%rbp\n\t"                                                  \
            "pushq %%rbx\n\t"                                                  \
            "pushq %%r12\n\t"                                                  \
            "pushq %%r13\n\t"                                                  \
            "pushq %%r14\n\t"                                                  \
            "pushq %%r15\n\t"                                                  \
            "movq %%rsp, %0\n\t"                                               \
            "movq %2, %%rsp\n\t"                                               \
            "leaq 1f(%%rip), %%rax\n\t"                                        \
            "movq %%rax, %1\n\t"                                               \
            "pushq %3\n\t"                                                     \
            "jmp __switch_to\n\t"                                              \
            "1:\n\t"                                                           \
            "popq %%r15\n\t"                                                   \
            "popq %%r14\n\t"                                                   \
            "popq %%r13\n\t"                                                   \
            "popq %%r12\n\t"                                                   \
            "popq %%rbx\n\t"                                                   \
            "popq %%rbp\n\t"                                                   \
            "popq %%rax\n\t"                                                   \
            : "=m"(prev->arch_context->rsp), "=m"(prev->arch_context->rip)     \
            : "m"(next->arch_context->rsp), "m"(next->arch_context->rip),      \
              "D"(prev), "S"(next)                                             \
            : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "cc", "memory");  \
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
