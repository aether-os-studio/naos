.section .text
.globl _start
.globl trap_vector
.globl init_trap_vector

.align 8
trap_vector:
    j trap_handler

init_trap_vector:
    la t0, trap_vector
    csrw stvec, t0
    li a0, 0
    ret

.align 4
trap_handler:
    addi sp, sp, -280
    
    sd x1,  0(sp)    // ra
    sd x2,  8(sp)    // sp (这里保存的是进入异常前的sp值)
    sd x3,  16(sp)   // gp
    sd x4,  24(sp)   // tp
    sd x5,  32(sp)   // t0
    sd x6,  40(sp)   // t1
    sd x7,  48(sp)   // t2
    sd x8,  56(sp)   // s0/fp
    sd x9,  64(sp)   // s1
    sd x10, 72(sp)   // a0
    sd x11, 80(sp)   // a1
    sd x12, 88(sp)   // a2
    sd x13, 96(sp)   // a3
    sd x14, 104(sp)  // a4
    sd x15, 112(sp)  // a5
    sd x16, 120(sp)  // a6
    sd x17, 128(sp)  // a7
    sd x18, 136(sp)  // s2
    sd x19, 144(sp)  // s3
    sd x20, 152(sp)  // s4
    sd x21, 160(sp)  // s5
    sd x22, 168(sp)  // s6
    sd x23, 176(sp)  // s7
    sd x24, 184(sp)  // s8
    sd x25, 192(sp)  // s9
    sd x26, 200(sp)  // s10
    sd x27, 208(sp)  // s11
    sd x28, 216(sp)  // t3
    sd x29, 224(sp)  // t4
    sd x30, 232(sp)  // t5
    sd x31, 240(sp)  // t6
    
    addi t0, sp, 280
    sd t0, 8(sp)
    
    csrr t0, sepc
    sd t0, 248(sp)   // sepc
    
    csrr t0, scause
    sd t0, 256(sp)   // scause
    
    csrr t0, stval
    sd t0, 264(sp)   // stval
    
    csrr t0, sstatus
    sd t0, 272(sp)   // sstatus
    
    mv a0, sp
    call handle_trap_c
    
    ld t0, 248(sp)   // sepc
    csrw sepc, t0
    
    ld t0, 272(sp)   // sstatus  
    csrw sstatus, t0
    
    ld x1,  0(sp)    // ra
    ld x3,  16(sp)   // gp
    ld x4,  24(sp)   // tp
    ld x5,  32(sp)   // t0
    ld x6,  40(sp)   // t1
    ld x7,  48(sp)   // t2
    ld x8,  56(sp)   // s0/fp
    ld x9,  64(sp)   // s1
    ld x10, 72(sp)   // a0
    ld x11, 80(sp)   // a1
    ld x12, 88(sp)   // a2
    ld x13, 96(sp)   // a3
    ld x14, 104(sp)  // a4
    ld x15, 112(sp)  // a5
    ld x16, 120(sp)  // a6
    ld x17, 128(sp)  // a7
    ld x18, 136(sp)  // s2
    ld x19, 144(sp)  // s3
    ld x20, 152(sp)  // s4
    ld x21, 160(sp)  // s5
    ld x22, 168(sp)  // s6
    ld x23, 176(sp)  // s7
    ld x24, 184(sp)  // s8
    ld x25, 192(sp)  // s9
    ld x26, 200(sp)  // s10
    ld x27, 208(sp)  // s11
    ld x28, 216(sp)  // t3
    ld x29, 224(sp)  // t4
    ld x30, 232(sp)  // t5
    ld x31, 240(sp)  // t6
    
    ld x2, 8(sp)     // 恢复原始sp值
    
    mret
