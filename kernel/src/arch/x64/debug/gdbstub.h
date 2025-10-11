#include <libs/klibc.h>
#include <arch/x64/irq/ptrace.h>

enum amd64_regnum {
    AMD64_RAX_REGNUM,      /* %rax */
    AMD64_RBX_REGNUM,      /* %rbx */
    AMD64_RCX_REGNUM,      /* %rcx */
    AMD64_RDX_REGNUM,      /* %rdx */
    AMD64_RSI_REGNUM,      /* %rsi */
    AMD64_RDI_REGNUM,      /* %rdi */
    AMD64_RBP_REGNUM,      /* %rbp */
    AMD64_RSP_REGNUM,      /* %rsp */
    AMD64_R8_REGNUM,       /* %r8 */
    AMD64_R9_REGNUM,       /* %r9 */
    AMD64_R10_REGNUM,      /* %r10 */
    AMD64_R11_REGNUM,      /* %r11 */
    AMD64_R12_REGNUM,      /* %r12 */
    AMD64_R13_REGNUM,      /* %r13 */
    AMD64_R14_REGNUM,      /* %r14 */
    AMD64_R15_REGNUM,      /* %r15 */
    AMD64_RIP_REGNUM,      /* %rip */
    AMD64_EFLAGS_REGNUM,   /* %eflags */
    AMD64_CS_REGNUM,       /* %cs */
    AMD64_SS_REGNUM,       /* %ss */
    AMD64_DS_REGNUM,       /* %ds */
    AMD64_ES_REGNUM,       /* %es */
    AMD64_FS_REGNUM,       /* %fs */
    AMD64_GS_REGNUM,       /* %gs */
    AMD64_ST0_REGNUM = 24, /* %st0 */
    AMD64_ST1_REGNUM,      /* %st1 */
    AMD64_FCTRL_REGNUM = AMD64_ST0_REGNUM + 8,
    AMD64_FSTAT_REGNUM = AMD64_ST0_REGNUM + 9,
    AMD64_FTAG_REGNUM = AMD64_ST0_REGNUM + 10,
    AMD64_XMM0_REGNUM = 40, /* %xmm0 */
    AMD64_XMM1_REGNUM,      /* %xmm1 */
    AMD64_MXCSR_REGNUM = AMD64_XMM0_REGNUM + 16,
    AMD64_YMM0H_REGNUM, /* %ymm0h */
    AMD64_YMM15H_REGNUM = AMD64_YMM0H_REGNUM + 15,
    /* MPX is deprecated.  Yet we keep this to not give the registers below
       a new number.  That could break older gdbservers.  */
    AMD64_BND0R_REGNUM = AMD64_YMM15H_REGNUM + 1,
    AMD64_BND3R_REGNUM = AMD64_BND0R_REGNUM + 3,
    AMD64_BNDCFGU_REGNUM,
    AMD64_BNDSTATUS_REGNUM,
    AMD64_XMM16_REGNUM,
    AMD64_XMM31_REGNUM = AMD64_XMM16_REGNUM + 15,
    AMD64_YMM16H_REGNUM,
    AMD64_YMM31H_REGNUM = AMD64_YMM16H_REGNUM + 15,
    AMD64_K0_REGNUM,
    AMD64_K7_REGNUM = AMD64_K0_REGNUM + 7,
    AMD64_ZMM0H_REGNUM,
    AMD64_ZMM31H_REGNUM = AMD64_ZMM0H_REGNUM + 31,
    AMD64_PKRU_REGNUM,
    AMD64_PL3_SSP_REGNUM,
    AMD64_FSBASE_REGNUM,
    AMD64_GSBASE_REGNUM,
    AMD64_REGNUM
};

struct hart_state {
    struct pt_regs registers;
};

static inline int hart_vector_stamp(struct hart_state *hstate) { return 0; }

static inline unsigned int hart_ecause(struct hart_state *hstate) { return 0; }

static inline struct hart_state *hart_parent_state(struct hart_state *hstate) {
    return 0;
}

static inline void hart_push_state(struct hart_state *p_hstate,
                                   struct hart_state *hstate) {}

static inline uintptr_t hart_pc(struct hart_state *hstate) {
    return hstate->registers.rip;
}

static inline uintptr_t hart_sp(struct hart_state *hstate) {
    return hstate->registers.rsp;
}

static inline bool kernel_context(struct hart_state *hstate) {
    return !(hstate->registers.cs & 0b11);
}

static inline uintptr_t hart_stack_frame(struct hart_state *hstate) {
    return hstate->registers.rbp;
}

struct gdb_state;

void arch_gdbstub_save_regs(struct gdb_state *state, struct hart_state *hstate);

void arch_gdbstub_restore_regs(struct gdb_state *state,
                               struct hart_state *hstate);

int gdb_sys_continue(struct gdb_state *state);

int gdb_sys_step(struct gdb_state *state);
