.section .text

.equ PT_RA,        0
.equ PT_SP,        8
.equ PT_GP,        16
.equ PT_TP,        24
.equ PT_T0,        32
.equ PT_T1,        40
.equ PT_T2,        48
.equ PT_T3,        56
.equ PT_T4,        64
.equ PT_T5,        72
.equ PT_T6,        80
.equ PT_T7,        88
.equ PT_T8,        96
.equ PT_R21,       104
.equ PT_FP,        112
.equ PT_S0,        120
.equ PT_S1,        128
.equ PT_S2,        136
.equ PT_S3,        144
.equ PT_S4,        152
.equ PT_S5,        160
.equ PT_S6,        168
.equ PT_S7,        176
.equ PT_S8,        184
.equ PT_A0,        192
.equ PT_A1,        200
.equ PT_A2,        208
.equ PT_A3,        216
.equ PT_A4,        224
.equ PT_A5,        232
.equ PT_A6,        240
.equ PT_A7,        248
.equ PT_PC,        256
.equ PT_USP,       264
.equ PT_CSR_PRMD,  272
.equ PT_CSR_ESTAT, 280
.equ PT_CSR_BADV,  288
.equ PT_SYSCALLNO, 296
.equ PT_SIZE,      304

.equ CSR_PRMD,     0x1
.equ CSR_ESTAT,    0x5
.equ CSR_ERA,      0x6
.equ CSR_BADV,     0x7

.equ CTX_RA,       0
.equ CTX_SP,       8
.equ CTX_FP,       16
.equ CTX_S0,       24
.equ CTX_S1,       32
.equ CTX_S2,       40
.equ CTX_S3,       48
.equ CTX_S4,       56
.equ CTX_S5,       64
.equ CTX_S6,       72
.equ CTX_S7,       80
.equ CTX_S8,       88

.global loongarch64_trap_entry
.align 12
loongarch64_trap_entry:
    addi.d $sp, $sp, -PT_SIZE
    st.d $ra, $sp, PT_RA
    st.d $zero, $sp, PT_GP
    st.d $tp, $sp, PT_TP
    st.d $t0, $sp, PT_T0
    st.d $t1, $sp, PT_T1
    st.d $t2, $sp, PT_T2
    st.d $t3, $sp, PT_T3
    st.d $t4, $sp, PT_T4
    st.d $t5, $sp, PT_T5
    st.d $t6, $sp, PT_T6
    st.d $t7, $sp, PT_T7
    st.d $t8, $sp, PT_T8
    st.d $r21, $sp, PT_R21
    st.d $fp, $sp, PT_FP
    st.d $s0, $sp, PT_S0
    st.d $s1, $sp, PT_S1
    st.d $s2, $sp, PT_S2
    st.d $s3, $sp, PT_S3
    st.d $s4, $sp, PT_S4
    st.d $s5, $sp, PT_S5
    st.d $s6, $sp, PT_S6
    st.d $s7, $sp, PT_S7
    st.d $s8, $sp, PT_S8
    st.d $a0, $sp, PT_A0
    st.d $a1, $sp, PT_A1
    st.d $a2, $sp, PT_A2
    st.d $a3, $sp, PT_A3
    st.d $a4, $sp, PT_A4
    st.d $a5, $sp, PT_A5
    st.d $a6, $sp, PT_A6
    st.d $a7, $sp, PT_A7

    addi.d $t0, $sp, PT_SIZE
    st.d $t0, $sp, PT_SP
    st.d $t0, $sp, PT_USP

    csrrd $t0, CSR_ERA
    st.d $t0, $sp, PT_PC
    csrrd $t0, CSR_PRMD
    st.d $t0, $sp, PT_CSR_PRMD
    csrrd $t0, CSR_ESTAT
    st.d $t0, $sp, PT_CSR_ESTAT
    csrrd $t0, CSR_BADV
    st.d $t0, $sp, PT_CSR_BADV
    li.d $t0, -1
    st.d $t0, $sp, PT_SYSCALLNO

    move $a0, $sp
    bl loongarch64_trap_dispatch

    ld.d $t0, $sp, PT_PC
    csrwr $t0, CSR_ERA
    ld.d $t0, $sp, PT_CSR_PRMD
    csrwr $t0, CSR_PRMD

    ld.d $ra, $sp, PT_RA
    ld.d $tp, $sp, PT_TP
    ld.d $t0, $sp, PT_T0
    ld.d $t1, $sp, PT_T1
    ld.d $t2, $sp, PT_T2
    ld.d $t3, $sp, PT_T3
    ld.d $t4, $sp, PT_T4
    ld.d $t5, $sp, PT_T5
    ld.d $t6, $sp, PT_T6
    ld.d $t7, $sp, PT_T7
    ld.d $t8, $sp, PT_T8
    ld.d $r21, $sp, PT_R21
    ld.d $fp, $sp, PT_FP
    ld.d $s0, $sp, PT_S0
    ld.d $s1, $sp, PT_S1
    ld.d $s2, $sp, PT_S2
    ld.d $s3, $sp, PT_S3
    ld.d $s4, $sp, PT_S4
    ld.d $s5, $sp, PT_S5
    ld.d $s6, $sp, PT_S6
    ld.d $s7, $sp, PT_S7
    ld.d $s8, $sp, PT_S8
    ld.d $a0, $sp, PT_A0
    ld.d $a1, $sp, PT_A1
    ld.d $a2, $sp, PT_A2
    ld.d $a3, $sp, PT_A3
    ld.d $a4, $sp, PT_A4
    ld.d $a5, $sp, PT_A5
    ld.d $a6, $sp, PT_A6
    ld.d $a7, $sp, PT_A7
    ld.d $sp, $sp, PT_SP
    ertn

.global loongarch64_switch_to
.align 8
loongarch64_switch_to:
    addi.d $sp, $sp, -16
    st.d $ra, $sp, 0
    st.d $a1, $sp, 8
    la.local $t0, 1f
    st.d $t0, $a0, CTX_RA
    st.d $sp, $a0, CTX_SP
    st.d $fp, $a0, CTX_FP
    st.d $s0, $a0, CTX_S0
    st.d $s1, $a0, CTX_S1
    st.d $s2, $a0, CTX_S2
    st.d $s3, $a0, CTX_S3
    st.d $s4, $a0, CTX_S4
    st.d $s5, $a0, CTX_S5
    st.d $s6, $a0, CTX_S6
    st.d $s7, $a0, CTX_S7
    st.d $s8, $a0, CTX_S8

    move $a0, $a2
    move $a1, $a3
    bl __switch_to

    ld.d $t0, $sp, 8
    ld.d $ra, $t0, CTX_RA
    ld.d $sp, $t0, CTX_SP
    ld.d $fp, $t0, CTX_FP
    ld.d $s0, $t0, CTX_S0
    ld.d $s1, $t0, CTX_S1
    ld.d $s2, $t0, CTX_S2
    ld.d $s3, $t0, CTX_S3
    ld.d $s4, $t0, CTX_S4
    ld.d $s5, $t0, CTX_S5
    ld.d $s6, $t0, CTX_S6
    ld.d $s7, $t0, CTX_S7
    ld.d $s8, $t0, CTX_S8
    jr $ra
1:
    ld.d $ra, $sp, 0
    addi.d $sp, $sp, 16
    jr $ra

.global kernel_thread_func
.align 8
kernel_thread_func:
    move $a0, $s1
    jirl $ra, $s0, 0
    li.d $a0, 0
    b task_exit_thread

.global ret_from_fork
.align 8
ret_from_fork:
    bl before_ret_from_fork
    b loongarch64_trap_return

.global loongarch64_trap_return
.align 8
loongarch64_trap_return:
    ld.d $t0, $sp, PT_PC
    csrwr $t0, CSR_ERA
    ld.d $t0, $sp, PT_CSR_PRMD
    csrwr $t0, CSR_PRMD
    ld.d $ra, $sp, PT_RA
    ld.d $tp, $sp, PT_TP
    ld.d $t0, $sp, PT_T0
    ld.d $t1, $sp, PT_T1
    ld.d $t2, $sp, PT_T2
    ld.d $t3, $sp, PT_T3
    ld.d $t4, $sp, PT_T4
    ld.d $t5, $sp, PT_T5
    ld.d $t6, $sp, PT_T6
    ld.d $t7, $sp, PT_T7
    ld.d $t8, $sp, PT_T8
    ld.d $r21, $sp, PT_R21
    ld.d $fp, $sp, PT_FP
    ld.d $s0, $sp, PT_S0
    ld.d $s1, $sp, PT_S1
    ld.d $s2, $sp, PT_S2
    ld.d $s3, $sp, PT_S3
    ld.d $s4, $sp, PT_S4
    ld.d $s5, $sp, PT_S5
    ld.d $s6, $sp, PT_S6
    ld.d $s7, $sp, PT_S7
    ld.d $s8, $sp, PT_S8
    ld.d $a0, $sp, PT_A0
    ld.d $a1, $sp, PT_A1
    ld.d $a2, $sp, PT_A2
    ld.d $a3, $sp, PT_A3
    ld.d $a4, $sp, PT_A4
    ld.d $a5, $sp, PT_A5
    ld.d $a6, $sp, PT_A6
    ld.d $a7, $sp, PT_A7
    ld.d $sp, $sp, PT_SP
    ertn
