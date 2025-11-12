.global kernel_thread_func
.type kernel_thread_func, @function
kernel_thread_func:
    /* SP 指向 pt_regs 结构的起始地址 */
    
    /* 跳过: pc, cpsr, sp_el0, x30, fpcr, fpsr (6 个字段 = 0x30 bytes) */
    add sp, sp, #0x30
    
    /* 恢复通用寄存器 (按照 pt_regs 结构顺序) */
    ldp x28, x29, [sp], #16     /* x28, x29 */
    ldp x26, x27, [sp], #16     /* x26, x27 */
    ldp x24, x25, [sp], #16     /* x24, x25 */
    ldp x22, x23, [sp], #16     /* x22, x23 */
    ldp x20, x21, [sp], #16     /* x20=参数, x21 */
    ldp x18, x19, [sp], #16     /* x18, x19=函数指针 */
    ldp x16, x17, [sp], #16     /* x16, x17 */
    ldp x14, x15, [sp], #16     /* x14, x15 */
    ldp x12, x13, [sp], #16     /* x12, x13 */
    ldp x10, x11, [sp], #16     /* x10, x11 */
    ldp x8, x9, [sp], #16       /* x8, x9 */
    ldp x6, x7, [sp], #16       /* x6, x7 */
    ldp x4, x5, [sp], #16       /* x4, x5 */
    ldp x2, x3, [sp], #16       /* x2, x3 */
    ldp x0, x1, [sp], #16       /* x0, x1 */
    
    add sp, sp, #0x100
    
    /* 调用内核线程函数: func(arg) */
    mov x0, x20                 /* x0 = 参数 (从 x20 传递) */
    blr x19                     /* 调用函数 (x19 = 函数指针) */
    
    /* 线程函数返回后，调用 task_exit */
    mov x0, xzr                 /* exit code = 0 */
    bl task_exit
