#include "arch/x64/asm.h"
#include "settings.h"

.section .data
.align 16
.global GDT_Table

GDT_Table:
    .quad 0x0000000000000000
    .quad 0x0020980000000000
    .quad 0x0000920000000000
    .quad 0x0000f20000000000
    .quad 0x0020f80000000000
    .quad 0x0000000000000000
    .quad 0x0000000000000000
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .fill (MAX_CPU_NUM * 2 + 1), 8, 0
GDT_END:

.global GDT_POINTER
GDT_POINTER:
GDT_LIMIT: .word GDT_END - GDT_Table - 1
GDT_BASE: .quad GDT_Table

.align 16
.global IDT_Table

IDT_Table:
    .fill 512, 8, 0
IDT_END:

.global IDT_POINTER
IDT_POINTER:
IDT_LIMIT: .word IDT_END - IDT_Table - 1
IDT_BASE: .quad IDT_Table

R15 =   0x00
R14 =   0x08
R13 =   0x10
R12 =   0x18
R11 =   0x20
R10 =   0x28
R9  =   0x30
R8  =   0x38
RBX =   0x40
RCX =   0x48
RDX =   0x50
RSI =   0x58
RDI	=	0x60
RBP	=	0x68
RAX	=	0x70
FUNC	=	0x78
ERRCODE	=	0x80
RIP	    =	0x88
CS	    =	0x90
RFLAGS	=	0x98
OLD_RSP	=	0xa0
OLDSS	=	0xa8

.section .text

ENTRY(ret_to_user)
ENTRY(ret_from_exception)
Restore_all:
    cli

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp

    popq %rax
    addq $0x10, %rsp // 弹出变量FUNC和errcode

    iretq

ENTRY(ret_from_intr)
    jmp Restore_all
    
Err_Code:
    cli

    pushq %rax

    xorq %rax, %rax

    pushq	%rbp
    pushq	%rdi
    pushq	%rsi
    pushq	%rdx
    pushq	%rcx
    pushq	%rbx
    pushq	%r8
    pushq	%r9
    pushq	%r10
    pushq	%r11
    pushq	%r12
    pushq	%r13
    pushq	%r14
    pushq	%r15

    cld

    movq ERRCODE(%rsp), %rsi    // 把错误码装进rsi，作为函数的第二个参数
    movq FUNC(%rsp), %rdx

    movq %rsp, %rdi // 把栈指针装入rdi，作为函数的第一个的参数

    callq *%rdx //调用服务程序 带*号表示调用的是绝对地址

    jmp ret_from_exception

// 0 #DE 除法错误
ENTRY(divide_error)
    pushq $0    //由于#DE不会产生错误码，但是为了保持弹出结构的一致性，故也压入一个错误码0
    pushq %rax  // 先将rax入栈
    leaq do_divide_error(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 1 #DB 调试异常
ENTRY(debug)
    pushq $0    
    pushq %rax  
    leaq do_debug(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 2 不可屏蔽中断
ENTRY(nmi)
    // 不可屏蔽中断不是异常，而是一个外部中断，不会产生错误码
    // 应执行中断处理流程
    pushq $0  //占位err_code

    pushq %rax
    leaq do_nmi(%rip), %rax
    xchgq %rax, (%rsp)
    jmp Err_Code

// 3 #BP 断点异常
ENTRY(int3)
    pushq $0
    pushq %rax
    leaq do_int3(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 4 #OF 溢出异常
ENTRY(overflow)
    pushq $0
    pushq %rax
    leaq do_overflow(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 5 #BR 越界异常
ENTRY(bounds)
    pushq $0
    pushq %rax
    leaq do_bounds(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 6 #UD 无效/未定义的机器码
ENTRY(undefined_opcode)
    pushq $0
    pushq %rax
    leaq do_undefined_opcode(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 7 #NM 设备异常（FPU不存在）
ENTRY(dev_not_avaliable)
    pushq $0
    pushq %rax
    leaq do_dev_not_avaliable(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 8 #DF 双重错误
ENTRY(double_fault)
    pushq %rax
    leaq do_double_fault(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 9 协处理器越界（保留）
ENTRY(coprocessor_segment_overrun)
    pushq $0
    pushq %rax
    leaq do_coprocessor_segment_overrun(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 10 #TS 无效的TSS段
ENTRY(invalid_TSS)
    // === 不正确的任务状态段 #TS ==
    // 有错误码,处理器已经自动在异常处理程序栈中压入错误码
    pushq %rax
    leaq do_invalid_TSS(%rip), %rax
    xchgq %rax, (%rsp)
    jmp Err_Code

// 11 #NP 段不存在
ENTRY(segment_not_exists)
    pushq %rax
    leaq do_segment_not_exists(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 12 #SS 段错误
ENTRY(stack_segment_fault)
    pushq %rax
    leaq do_stack_segment_fault(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 13 #GP 通用保护性异常
ENTRY(general_protection)
    pushq %rax
    leaq do_general_protection(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 14 #PF 页错误
ENTRY(page_fault)
    // === 页故障 #PF ==
    // 有错误码
    pushq %rax
    leaq do_page_fault(%rip), %rax
    xchgq %rax, (%rsp)
    jmp Err_Code

// 15 Intel保留，请勿使用

// 16 #MF X87 FPU错误（计算错误）
ENTRY(x87_FPU_error)
    pushq $0
    pushq %rax
    leaq do_x87_FPU_error(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 17 #AC 对齐检测
ENTRY(alignment_check)
    pushq %rax
    leaq do_alignment_check(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 18 #MC 机器检测
ENTRY(machine_check)
    pushq $0
    pushq %rax
    leaq do_machine_check(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 19 #XM SIMD浮点异常
ENTRY(SIMD_exception)
    pushq $0
    pushq %rax
    leaq do_SIMD_exception(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 20 #VE 虚拟化异常
ENTRY(virtualization_exception)
    pushq $0
    pushq %rax
    leaq do_virtualization_exception(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

// 0x80 系统调用异常
ENTRY(syscall_exception)
    pushq $0
    pushq %rax
    leaq do_syscall_exception(%rip), %rax    // 获取中断服务程序的地址
    xchgq %rax, (%rsp)  // 把FUNC的地址换入栈中
    jmp Err_Code

ENTRY(gdtidt_setup)
    lidt IDT_POINTER(%rip)

    lgdt GDT_POINTER(%rip)

    movq ready_to_ret(%rip), %rax
    pushq $0x08
    pushq %rax
    lretq

ready_to_ret:
    .quad to_ret

to_ret:
    movq $0x10, %rax
    movq %rax, %ds
    movq %rax, %es
    movq %rax, %ss
    movq $0x0, %rax
    movq %rax, %fs
    movq %rax, %gs

    ret
