.section .text

.equ PT_RA,       0
.equ PT_SP,       8
.equ PT_GP,       16
.equ PT_TP,       24
.equ PT_T0,       32
.equ PT_T1,       40
.equ PT_T2,       48
.equ PT_S0,       56
.equ PT_S1,       64
.equ PT_A0,       72
.equ PT_A1,       80
.equ PT_A2,       88
.equ PT_A3,       96
.equ PT_A4,       104
.equ PT_A5,       112
.equ PT_A6,       120
.equ PT_A7,       128
.equ PT_S2,       136
.equ PT_S3,       144
.equ PT_S4,       152
.equ PT_S5,       160
.equ PT_S6,       168
.equ PT_S7,       176
.equ PT_S8,       184
.equ PT_S9,       192
.equ PT_S10,      200
.equ PT_S11,      208
.equ PT_T3,       216
.equ PT_T4,       224
.equ PT_T5,       232
.equ PT_T6,       240
.equ PT_SEPC,     248
.equ PT_SSTATUS,  256
.equ PT_STVAL,    264
.equ PT_SCAUSE,   272
.equ PT_SYSCALLNO,280
.equ PT_SIZE,     288

.equ CPU_LOCAL_SYSCALL_STACK,   0
.equ CPU_LOCAL_USER_SP_SCRATCH, 8
.equ CPU_LOCAL_TRAP_T0_SCRATCH, 16

.equ SSTATUS_SPP, 0x100

.align 2
.global riscv64_trap_return
riscv64_trap_return:
    ld t0, PT_SEPC(sp)
    csrw sepc, t0
    ld t0, PT_SSTATUS(sp)
    csrw sstatus, t0
    andi t1, t0, SSTATUS_SPP
    beqz t1, 1f

    ld ra, PT_RA(sp)
    ld gp, PT_GP(sp)
    ld tp, PT_TP(sp)
    ld t0, PT_T0(sp)
    ld t1, PT_T1(sp)
    ld t2, PT_T2(sp)
    ld s0, PT_S0(sp)
    ld s1, PT_S1(sp)
    ld a0, PT_A0(sp)
    ld a1, PT_A1(sp)
    ld a2, PT_A2(sp)
    ld a3, PT_A3(sp)
    ld a4, PT_A4(sp)
    ld a5, PT_A5(sp)
    ld a6, PT_A6(sp)
    ld a7, PT_A7(sp)
    ld s2, PT_S2(sp)
    ld s3, PT_S3(sp)
    ld s4, PT_S4(sp)
    ld s5, PT_S5(sp)
    ld s6, PT_S6(sp)
    ld s7, PT_S7(sp)
    ld s8, PT_S8(sp)
    ld s9, PT_S9(sp)
    ld s10, PT_S10(sp)
    ld s11, PT_S11(sp)
    ld t3, PT_T3(sp)
    ld t4, PT_T4(sp)
    ld t5, PT_T5(sp)
    ld t6, PT_T6(sp)
    ld sp, PT_SP(sp)
    sret

1:
    ld ra, PT_RA(sp)
    ld gp, PT_GP(sp)
    ld tp, PT_TP(sp)
    ld t0, PT_T0(sp)
    ld t1, PT_T1(sp)
    ld t2, PT_T2(sp)
    ld s0, PT_S0(sp)
    ld s1, PT_S1(sp)
    ld a0, PT_A0(sp)
    ld a1, PT_A1(sp)
    ld a2, PT_A2(sp)
    ld a3, PT_A3(sp)
    ld a4, PT_A4(sp)
    ld a5, PT_A5(sp)
    ld a6, PT_A6(sp)
    ld a7, PT_A7(sp)
    ld s2, PT_S2(sp)
    ld s3, PT_S3(sp)
    ld s4, PT_S4(sp)
    ld s5, PT_S5(sp)
    ld s6, PT_S6(sp)
    ld s7, PT_S7(sp)
    ld s8, PT_S8(sp)
    ld s9, PT_S9(sp)
    ld s10, PT_S10(sp)
    ld s11, PT_S11(sp)
    ld t3, PT_T3(sp)
    ld t4, PT_T4(sp)
    ld t5, PT_T5(sp)
    ld t6, PT_T6(sp)
    ld sp, PT_SP(sp)
    sret

.align 2
.global riscv64_trap_entry
riscv64_trap_entry:
    csrrw tp, sscratch, tp
    sd t0, CPU_LOCAL_TRAP_T0_SCRATCH(tp)
    csrr t0, sstatus
    andi t0, t0, SSTATUS_SPP
    beqz t0, 1f

    addi sp, sp, -PT_SIZE
    sd ra, PT_RA(sp)
    sd gp, PT_GP(sp)
    csrr t0, sscratch
    sd t0, PT_TP(sp)
    ld t0, CPU_LOCAL_TRAP_T0_SCRATCH(tp)
    sd t0, PT_T0(sp)
    sd t1, PT_T1(sp)
    sd t2, PT_T2(sp)
    sd s0, PT_S0(sp)
    sd s1, PT_S1(sp)
    sd a0, PT_A0(sp)
    sd a1, PT_A1(sp)
    sd a2, PT_A2(sp)
    sd a3, PT_A3(sp)
    sd a4, PT_A4(sp)
    sd a5, PT_A5(sp)
    sd a6, PT_A6(sp)
    sd a7, PT_A7(sp)
    sd s2, PT_S2(sp)
    sd s3, PT_S3(sp)
    sd s4, PT_S4(sp)
    sd s5, PT_S5(sp)
    sd s6, PT_S6(sp)
    sd s7, PT_S7(sp)
    sd s8, PT_S8(sp)
    sd s9, PT_S9(sp)
    sd s10, PT_S10(sp)
    sd s11, PT_S11(sp)
    sd t3, PT_T3(sp)
    sd t4, PT_T4(sp)
    sd t5, PT_T5(sp)
    sd t6, PT_T6(sp)

    addi t0, sp, PT_SIZE
    sd t0, PT_SP(sp)
    csrw sscratch, tp
    j 3f

1:
    sd sp, CPU_LOCAL_USER_SP_SCRATCH(tp)
    ld sp, CPU_LOCAL_SYSCALL_STACK(tp)
    addi sp, sp, -PT_SIZE
    sd ra, PT_RA(sp)
    sd gp, PT_GP(sp)
    csrr t0, sscratch
    sd t0, PT_TP(sp)
    ld t0, CPU_LOCAL_TRAP_T0_SCRATCH(tp)
    sd t0, PT_T0(sp)
    sd t1, PT_T1(sp)
    sd t2, PT_T2(sp)
    sd s0, PT_S0(sp)
    sd s1, PT_S1(sp)
    sd a0, PT_A0(sp)
    sd a1, PT_A1(sp)
    sd a2, PT_A2(sp)
    sd a3, PT_A3(sp)
    sd a4, PT_A4(sp)
    sd a5, PT_A5(sp)
    sd a6, PT_A6(sp)
    sd a7, PT_A7(sp)
    sd s2, PT_S2(sp)
    sd s3, PT_S3(sp)
    sd s4, PT_S4(sp)
    sd s5, PT_S5(sp)
    sd s6, PT_S6(sp)
    sd s7, PT_S7(sp)
    sd s8, PT_S8(sp)
    sd s9, PT_S9(sp)
    sd s10, PT_S10(sp)
    sd s11, PT_S11(sp)
    sd t3, PT_T3(sp)
    sd t4, PT_T4(sp)
    sd t5, PT_T5(sp)
    sd t6, PT_T6(sp)

    ld t0, CPU_LOCAL_USER_SP_SCRATCH(tp)
    sd t0, PT_SP(sp)
    csrw sscratch, tp

3:

    csrr t0, sepc
    sd t0, PT_SEPC(sp)
    csrr t0, sstatus
    sd t0, PT_SSTATUS(sp)
    csrr t0, stval
    sd t0, PT_STVAL(sp)
    csrr t0, scause
    sd t0, PT_SCAUSE(sp)
    li t0, -1
    sd t0, PT_SYSCALLNO(sp)

    mv a0, sp
    call trap_dispatch

    j riscv64_trap_return

.align 2
.global setup_trap_vector
setup_trap_vector:
    la t0, riscv64_trap_entry
    csrw stvec, t0
    ret

.align 2
.global ret_from_fork
ret_from_fork:
    call before_ret_from_fork
    j riscv64_trap_return

.align 2
.global kernel_thread_func
kernel_thread_func:
    mv a0, s1
    jalr s0
    li a0, 0
    tail task_exit_thread
