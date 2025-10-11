#include <debug/gdbstub.h>

void arch_gdbstub_save_regs(struct gdb_state *state,
                            struct hart_state *hstate) {
    /* Load Registers */
#if defined(__x86_64__)
    state->registers[AMD64_RAX_REGNUM] = hstate->registers.rax;
    state->registers[AMD64_RCX_REGNUM] = hstate->registers.rcx;
    state->registers[AMD64_RDX_REGNUM] = hstate->registers.rdx;
    state->registers[AMD64_RBX_REGNUM] = hstate->registers.rbx;
    state->registers[AMD64_RSP_REGNUM] = hstate->registers.rsp;
    state->registers[AMD64_RBP_REGNUM] = hstate->registers.rbp;
    state->registers[AMD64_RSI_REGNUM] = hstate->registers.rsi;
    state->registers[AMD64_RDI_REGNUM] = hstate->registers.rdi;
    state->registers[AMD64_RIP_REGNUM] = hstate->registers.rip;
    state->registers[AMD64_CS_REGNUM] = hstate->registers.cs;
    state->registers[AMD64_EFLAGS_REGNUM] = hstate->registers.rflags;
    state->registers[AMD64_SS_REGNUM] = hstate->registers.ss;
    state->registers[AMD64_DS_REGNUM] = hstate->registers.ds;
    state->registers[AMD64_ES_REGNUM] = hstate->registers.es;
    state->registers[AMD64_FS_REGNUM] = hstate->registers.ss;
    state->registers[AMD64_GS_REGNUM] = hstate->registers.ss;
    state->registers[AMD64_FSBASE_REGNUM] = read_fsbase();
    state->registers[AMD64_GSBASE_REGNUM] = read_gsbase();
#endif
}

void arch_gdbstub_restore_regs(struct gdb_state *state,
                               struct hart_state *hstate) {
#if defined(__x86_64__)
    hstate->registers.rax = state->registers[AMD64_RAX_REGNUM];
    hstate->registers.rcx = state->registers[AMD64_RCX_REGNUM];
    hstate->registers.rdx = state->registers[AMD64_RDX_REGNUM];
    hstate->registers.rbx = state->registers[AMD64_RBX_REGNUM];
    hstate->registers.rsp = state->registers[AMD64_RSP_REGNUM];
    hstate->registers.rbp = state->registers[AMD64_RBP_REGNUM];
    hstate->registers.rsi = state->registers[AMD64_RSI_REGNUM];
    hstate->registers.rdi = state->registers[AMD64_RDI_REGNUM];
    hstate->registers.rip = state->registers[AMD64_RIP_REGNUM];
    hstate->registers.cs = state->registers[AMD64_CS_REGNUM];
    hstate->registers.rflags = state->registers[AMD64_EFLAGS_REGNUM];
    hstate->registers.ss = state->registers[AMD64_SS_REGNUM];
    hstate->registers.ds = state->registers[AMD64_DS_REGNUM];
    hstate->registers.es = state->registers[AMD64_ES_REGNUM];
#endif
}

int gdb_sys_continue(struct gdb_state *state) {
    state->registers[AMD64_EFLAGS_REGNUM] &= ~(1 << 8);
    return 0;
}

int gdb_sys_step(struct gdb_state *state) {
    state->registers[AMD64_EFLAGS_REGNUM] |= (1 << 8);
    return 0;
}
