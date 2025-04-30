#include "settings.h"

// https://gitee.com/BookOS/nxos/blob/master/src/arch/aarch64/kernel/vector.S

.macro SAVE_FPU, reg
    STR Q0, [\reg, #-0x10]!
    STR Q1, [\reg, #-0x10]!
    STR Q2, [\reg, #-0x10]!
    STR Q3, [\reg, #-0x10]!
    STR Q4, [\reg, #-0x10]!
    STR Q5, [\reg, #-0x10]!
    STR Q6, [\reg, #-0x10]!
    STR Q7, [\reg, #-0x10]!
    STR Q8, [\reg, #-0x10]!
    STR Q9, [\reg, #-0x10]!
    STR Q10, [\reg, #-0x10]!
    STR Q11, [\reg, #-0x10]!
    STR Q12, [\reg, #-0x10]!
    STR Q13, [\reg, #-0x10]!
    STR Q14, [\reg, #-0x10]!
    STR Q15, [\reg, #-0x10]!
.endm

.macro RESTORE_FPU, reg
    LDR Q15, [\reg], #0x10
    LDR Q14, [\reg], #0x10
    LDR Q13, [\reg], #0x10
    LDR Q12, [\reg], #0x10
    LDR Q11, [\reg], #0x10
    LDR Q10, [\reg], #0x10
    LDR Q9, [\reg], #0x10
    LDR Q8, [\reg], #0x10
    LDR Q7, [\reg], #0x10
    LDR Q6, [\reg], #0x10
    LDR Q5, [\reg], #0x10
    LDR Q4, [\reg], #0x10
    LDR Q3, [\reg], #0x10
    LDR Q2, [\reg], #0x10
    LDR Q1, [\reg], #0x10
    LDR Q0, [\reg], #0x10
.endm

.macro SAVE_CONTEXT
    /* Save the entire context. */
    SAVE_FPU SP
    STP     X0, X1, [SP, #-0x10]!
    STP     X2, X3, [SP, #-0x10]!
    STP     X4, X5, [SP, #-0x10]!
    STP     X6, X7, [SP, #-0x10]!
    STP     X8, X9, [SP, #-0x10]!
    STP     X10, X11, [SP, #-0x10]!
    STP     X12, X13, [SP, #-0x10]!
    STP     X14, X15, [SP, #-0x10]!
    STP     X16, X17, [SP, #-0x10]!
    STP     X18, X19, [SP, #-0x10]!
    STP     X20, X21, [SP, #-0x10]!
    STP     X22, X23, [SP, #-0x10]!
    STP     X24, X25, [SP, #-0x10]!
    STP     X26, X27, [SP, #-0x10]!
    STP     X28, X29, [SP, #-0x10]!
    MRS     X28, FPCR
    MRS     X29, FPSR
    STP     X28, X29, [SP, #-0x10]!
    MRS     X29, SP_EL0
    STP     X29, X30, [SP, #-0x10]!

    MRS     X3, SPSR_EL1
    MRS     X2, ELR_EL1

    STP     X2, X3, [SP, #-0x10]!

    MOV     X0, SP   /* Move SP into X0 for saving. */
.endm

.macro SAVE_CONTEXT_FROM_EL1
    /* Save the entire context. */
    SAVE_FPU SP
    STP     X0, X1, [SP, #-0x10]!
    STP     X2, X3, [SP, #-0x10]!
    STP     X4, X5, [SP, #-0x10]!
    STP     X6, X7, [SP, #-0x10]!
    STP     X8, X9, [SP, #-0x10]!
    STP     X10, X11, [SP, #-0x10]!
    STP     X12, X13, [SP, #-0x10]!
    STP     X14, X15, [SP, #-0x10]!
    STP     X16, X17, [SP, #-0x10]!
    STP     X18, X19, [SP, #-0x10]!
    STP     X20, X21, [SP, #-0x10]!
    STP     X22, X23, [SP, #-0x10]!
    STP     X24, X25, [SP, #-0x10]!
    STP     X26, X27, [SP, #-0x10]!
    STP     X28, X29, [SP, #-0x10]!
    MRS     X28, FPCR
    MRS     X29, FPSR
    STP     X28, X29, [SP, #-0x10]!
    MRS     X29, SP_EL0
    STP     X29, X30, [SP, #-0x10]!

    MOV     X19, #((3 << 6) | 0x4 | 0x1)  /* el1h, disable interrupt */
    MOV     X18, X30

    STP     X18, X19, [SP, #-0x10]!
.endm

.macro RESTORE_CONTEXT
    /* Set the SP to point to the stack of the task being restored. */
    MOV     SP, X0

    LDP     X2, X3, [SP], #0x10  /* SPSR and ELR. */

    TST     X3, #0x1f
    MSR     SPSR_EL1, X3
    MSR     ELR_EL1, X2

    LDP     X29, X30, [SP], #0x10
    MSR     SP_EL0, X29
    LDP     X28, X29, [SP], #0x10
    MSR     FPCR, X28
    MSR     FPSR, X29
    LDP     X28, X29, [SP], #0x10
    LDP     X26, X27, [SP], #0x10
    LDP     X24, X25, [SP], #0x10
    LDP     X22, X23, [SP], #0x10
    LDP     X20, X21, [SP], #0x10
    LDP     X18, X19, [SP], #0x10
    LDP     X16, X17, [SP], #0x10
    LDP     X14, X15, [SP], #0x10
    LDP     X12, X13, [SP], #0x10
    LDP     X10, X11, [SP], #0x10
    LDP     X8, X9, [SP], #0x10
    LDP     X6, X7, [SP], #0x10
    LDP     X4, X5, [SP], #0x10
    LDP     X2, X3, [SP], #0x10
    LDP     X0, X1, [SP], #0x10
    RESTORE_FPU SP

    ERET
.endm

#define BAD_SYNC        0
#define BAD_IRQ         1
#define BAD_FIQ         2
#define BAD_ERROR       3

/*
   vector table entry
   每个表项是128字节， align 7表示128字节对齐
 */
.macro vtentry label
.align 7
b \label
.endm

/*
   处理无效的异常向量
 */
.macro inv_entry reason
SAVE_CONTEXT
mov x0, sp
mov x1, #\reason
mrs x2, esr_el1
b bad_mode
.endm

/*
 * Vector Table
 *
 * ARM64的异常向量表一共占用2048个字节
 * 分成4组，每组4个表项，每个表项占128字节
 * 参见ARMv8 spec v8.6第D1.10节
 * align 11表示2048字节对齐
 */
.align 11
.global vectors
vectors:
	/* Current EL with SP0
	   当前系统运行在EL1时使用EL0的栈指针SP
	   这是一种异常错误的类型
	 */
	vtentry el1_sync_invalid
	vtentry el1_irq_invalid
	vtentry el1_fiq_invalid
	vtentry el1_error_invalid

	/* Current EL with SPx
	   当前系统运行在EL1时使用EL1的栈指针SP
	   这说明系统在内核态发生了异常

	   Note: 我们暂时只实现IRQ中断
	 */
	vtentry el1_sync_invalid
	vtentry el1_irq
	vtentry el1_fiq_invalid
	vtentry el1_error_invalid

	/* Lower EL using AArch64
	   在用户态的aarch64的程序发生了异常
	 */
	vtentry el0_sync
	vtentry el0_irq
	vtentry el0_fiq_invalid
	vtentry el0_error_invalid

	/* Lower EL using AArch32
	   在用户态的aarch32的程序发生了异常
	 */
	vtentry el0_sync_invalid
	vtentry el0_irq_invalid
	vtentry el0_fiq_invalid
	vtentry el0_error_invalid

el1_sync_invalid:
	inv_entry BAD_SYNC
el1_irq_invalid:
	inv_entry BAD_IRQ
el1_fiq_invalid:
	inv_entry BAD_FIQ
el1_error_invalid:
	inv_entry BAD_ERROR
el0_sync_invalid:
	inv_entry BAD_SYNC
el0_irq_invalid:
	inv_entry BAD_IRQ
el0_fiq_invalid:
	inv_entry BAD_FIQ
el0_error_invalid:
	inv_entry BAD_ERROR

.align 3
.global arch_context_switch_exit
arch_context_switch_exit:
    CLREX
    MOV     X0, SP
    RESTORE_CONTEXT

.align 3
el0_irq:
	SAVE_CONTEXT
	bl aarch64_do_irq
	B arch_context_switch_exit

.align 3
el0_sync:
	SAVE_CONTEXT
	STP     X0, X1, [SP, #-0x10]!
    BL      trap_dispatch
    LDP     X0, X1, [SP], #0x10
    MOV     SP, X0
	B arch_context_switch_exit

.align 3
el1_irq:
	SAVE_CONTEXT
	bl aarch64_do_irq
	B arch_context_switch_exit

.global setup_vectors
setup_vectors:
    /* setup vectors */
    ldr     x5, =vectors
	msr     vbar_el1, x5
	isb

    /* Set CPACR_EL1 (Architecture Feature Access Control Register) to avoid trap from SIMD or float point instruction */
    mov     x1, #0x00300000         /* Don't trap any SIMD/FP instructions in both EL0 and EL1 */
    msr     cpacr_el1, x1

    ret
