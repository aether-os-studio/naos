.global kernel_thread_func
.type kernel_thread_func, @function
kernel_thread_func:
    /* SP 指向 pt_regs 结构的起始地址 */
    
    /* 跳过: pc, cpsr, sp_el0, x30, origin_x0, reserved (6 个字段 = 0x30 bytes) */
    add sp, sp, #0x30
    
    ldp X28, X29, [SP], #0x10
    ldp X26, X27, [SP], #0x10
    ldp X24, X25, [SP], #0x10
    ldp X22, X23, [SP], #0x10
    ldp X20, X21, [SP], #0x10
    ldp X18, X19, [SP], #0x10
    ldp X16, X17, [SP], #0x10
    ldp X14, X15, [SP], #0x10
    ldp X12, X13, [SP], #0x10
    ldp X10, X11, [SP], #0x10
    ldp X8, X9, [SP], #0x10
    ldp X6, X7, [SP], #0x10
    ldp X4, X5, [SP], #0x10
    ldp X2, X3, [SP], #0x10
    ldp X0, X1, [SP], #0x10

    mov x0, x20
    blr x19
    
    /* 线程函数返回后，调用 task_exit */
    mov x0, xzr                 /* exit code = 0 */
    bl task_exit
