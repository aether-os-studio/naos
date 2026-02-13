#define PT_R0       0
#define PT_RA       8
#define PT_TP       16
#define PT_USP      24
#define PT_A0       32
#define PT_A1       40
#define PT_A2       48
#define PT_A3       56
#define PT_A4       64
#define PT_A5       72
#define PT_A6       80
#define PT_A7       88
#define PT_T0       96
#define PT_T1       104
#define PT_T2       112
#define PT_T3       120
#define PT_T4       128
#define PT_T5       136
#define PT_T6       144
#define PT_T7       152
#define PT_T8       160
#define PT_R21      168
#define PT_FP       176
#define PT_S0       184
#define PT_S1       192
#define PT_S2       200
#define PT_S3       208
#define PT_S4       216
#define PT_S5       224
#define PT_S6       232
#define PT_S7       240
#define PT_S8       248
#define PT_ORIG_A0  256

#define PT_ERA      264
#define PT_BADVADDR 272
#define PT_CRMD     280
#define PT_PRMD     288
#define PT_EUEN     296
#define PT_ECFG     304
#define PT_ESTAT    312

#define PT_SIZE     320

#define LOONGARCH_CSR_CRMD          0x0
#define LOONGARCH_CSR_PRMD          0x1
#define LOONGARCH_CSR_EUEN          0x2
#define LOONGARCH_CSR_ECFG          0x4
#define LOONGARCH_CSR_ESTAT         0x5
#define LOONGARCH_CSR_ERA           0x6
#define LOONGARCH_CSR_BADV          0x7
#define LOONGARCH_CSR_EENTRY        0xC
#define LOONGARCH_CSR_TLBIDX        0x10
#define LOONGARCH_CSR_TLBEHI        0x11
#define LOONGARCH_CSR_TLBELO0       0x12
#define LOONGARCH_CSR_TLBELO1       0x13
#define LOONGARCH_CSR_ASID          0x18
#define LOONGARCH_CSR_PGDL          0x19
#define LOONGARCH_CSR_PGDH          0x1A
#define LOONGARCH_CSR_PGD           0x1B
#define LOONGARCH_CSR_PWCL          0x1C
#define LOONGARCH_CSR_PWCH          0x1D
#define LOONGARCH_CSR_STLBPS        0x1E
#define LOONGARCH_CSR_RVACFG        0x1F

#define LOONGARCH_CSR_KS0           0x30
#define LOONGARCH_CSR_KS1           0x31

#define LOONGARCH_CSR_TLBRENTRY     0x88
#define LOONGARCH_CSR_TLBRSAVE      0x8B
#define LOONGARCH_CSR_TLBRELO0      0x8C
#define LOONGARCH_CSR_TLBRELO1      0x8D
#define LOONGARCH_CSR_TLBREHI       0x8E
#define LOONGARCH_CSR_TLBRPRMD      0x8F

#define LOONGARCH_CSR_DMWIN0        0x180
#define LOONGARCH_CSR_DMWIN1        0x181
#define LOONGARCH_CSR_DMWIN2        0x182
#define LOONGARCH_CSR_DMWIN3        0x183

.section .text
.align 12
.globl trap_entry
trap_entry:
    # 保存 t0, t1 到暂存 CSR
    csrwr   $t0, LOONGARCH_CSR_KS0
    csrwr   $t1, LOONGARCH_CSR_KS1
    
    # 在栈上分配 pt_regs 空间
    move    $t0, $sp
    addi.d  $sp, $sp, -PT_SIZE
    
    # 保存通用寄存器
    st.d    $r0,  $sp, PT_R0
    st.d    $ra,  $sp, PT_RA
    st.d    $tp,  $sp, PT_TP
    st.d    $t0,  $sp, PT_USP      # 原始 sp
    
    st.d    $a0,  $sp, PT_A0
    st.d    $a1,  $sp, PT_A1
    st.d    $a2,  $sp, PT_A2
    st.d    $a3,  $sp, PT_A3
    st.d    $a4,  $sp, PT_A4
    st.d    $a5,  $sp, PT_A5
    st.d    $a6,  $sp, PT_A6
    st.d    $a7,  $sp, PT_A7
    
    # 恢复 t0, t1 并保存
    csrrd   $t0, LOONGARCH_CSR_KS0
    csrrd   $t1, LOONGARCH_CSR_KS1
    st.d    $t0,  $sp, PT_T0
    st.d    $t1,  $sp, PT_T1
    
    st.d    $t2,  $sp, PT_T2
    st.d    $t3,  $sp, PT_T3
    st.d    $t4,  $sp, PT_T4
    st.d    $t5,  $sp, PT_T5
    st.d    $t6,  $sp, PT_T6
    st.d    $t7,  $sp, PT_T7
    st.d    $t8,  $sp, PT_T8
    st.d    $r21, $sp, PT_R21
    st.d    $fp,  $sp, PT_FP
    
    st.d    $s0,  $sp, PT_S0
    st.d    $s1,  $sp, PT_S1
    st.d    $s2,  $sp, PT_S2
    st.d    $s3,  $sp, PT_S3
    st.d    $s4,  $sp, PT_S4
    st.d    $s5,  $sp, PT_S5
    st.d    $s6,  $sp, PT_S6
    st.d    $s7,  $sp, PT_S7
    st.d    $s8,  $sp, PT_S8
    
    # 保存 orig_a0
    st.d    $a0,  $sp, PT_ORIG_A0
    
    # 保存 CSR 寄存器
    csrrd   $t0, LOONGARCH_CSR_ERA
    st.d    $t0, $sp, PT_ERA
    
    csrrd   $t0, LOONGARCH_CSR_BADV
    st.d    $t0, $sp, PT_BADVADDR
    
    csrrd   $t0, LOONGARCH_CSR_CRMD
    st.d    $t0, $sp, PT_CRMD
    
    csrrd   $t0, LOONGARCH_CSR_PRMD
    st.d    $t0, $sp, PT_PRMD
    
    csrrd   $t0, LOONGARCH_CSR_EUEN
    st.d    $t0, $sp, PT_EUEN
    
    csrrd   $t0, LOONGARCH_CSR_ECFG
    st.d    $t0, $sp, PT_ECFG
    
    csrrd   $t0, LOONGARCH_CSR_ESTAT
    st.d    $t0, $sp, PT_ESTAT
    
    move    $a0, $sp
    bl      trap_handle_c
    
    b       trap_return

.globl trap_return
trap_return:
    // 恢复 CSR 寄存器
    ld.d    $t0, $sp, PT_PRMD
    csrwr   $t0, LOONGARCH_CSR_PRMD
    
    ld.d    $t0, $sp, PT_EUEN
    csrwr   $t0, LOONGARCH_CSR_EUEN
    
    ld.d    $t0, $sp, PT_ERA
    csrwr   $t0, LOONGARCH_CSR_ERA
    
    // 恢复通用寄存器
    ld.d    $r0,  $sp, PT_R0
    ld.d    $ra,  $sp, PT_RA
    ld.d    $tp,  $sp, PT_TP
    
    ld.d    $a0,  $sp, PT_A0
    ld.d    $a1,  $sp, PT_A1
    ld.d    $a2,  $sp, PT_A2
    ld.d    $a3,  $sp, PT_A3
    ld.d    $a4,  $sp, PT_A4
    ld.d    $a5,  $sp, PT_A5
    ld.d    $a6,  $sp, PT_A6
    ld.d    $a7,  $sp, PT_A7
    
    ld.d    $t0,  $sp, PT_T0
    ld.d    $t1,  $sp, PT_T1
    ld.d    $t2,  $sp, PT_T2
    ld.d    $t3,  $sp, PT_T3
    ld.d    $t4,  $sp, PT_T4
    ld.d    $t5,  $sp, PT_T5
    ld.d    $t6,  $sp, PT_T6
    ld.d    $t7,  $sp, PT_T7
    ld.d    $t8,  $sp, PT_T8
    ld.d    $r21, $sp, PT_R21
    ld.d    $fp,  $sp, PT_FP
    
    ld.d    $s0,  $sp, PT_S0
    ld.d    $s1,  $sp, PT_S1
    ld.d    $s2,  $sp, PT_S2
    ld.d    $s3,  $sp, PT_S3
    ld.d    $s4,  $sp, PT_S4
    ld.d    $s5,  $sp, PT_S5
    ld.d    $s6,  $sp, PT_S6
    ld.d    $s7,  $sp, PT_S7
    ld.d    $s8,  $sp, PT_S8
    
    // 恢复原始栈指针
    ld.d    $sp,  $sp, PT_USP
    
    // 异常返回
    ertn
