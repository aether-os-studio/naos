#include "settings.h"

// https://gitee.com/BookOS/nxos/blob/master/src/arch/aarch64/kernel/vector.S

.macro SAVE_CONTEXT
    /* Save GPRs plus the minimum exception return state. */
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
    MRS     X29, SP_EL0
    STP     X29, X30, [SP, #-0x10]!
    MOV     X29, #0
    STP     X0, X29, [SP, #-0x10]!

    MRS     X3, SPSR_EL1
    MRS     X2, ELR_EL1

    STP     X2, X3, [SP, #-0x10]!

    MOV     X0, SP   /* Move SP into X0 for saving. */
.endm

.macro RESTORE_CONTEXT
    /* Set the SP to point to the stack of the task being restored. */
    MOV     SP, X0

    LDP     X2, X3, [SP], #0x10  /* SPSR and ELR. */
    MSR     SPSR_EL1, X3
    MSR     ELR_EL1, X2

    LDP     X0, X1, [SP], #0x10  /* origin_x0 and reserved */

    LDP     X29, X30, [SP], #0x10
    MSR     SP_EL0, X29
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

    ERET
.endm

#define BAD_SYNC 0
#define BAD_IRQ 1
#define BAD_FIQ 2
#define BAD_ERROR 3

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
	vtentry el1_sync_invalid
	vtentry el1_irq_invalid
	vtentry el1_fiq_invalid
	vtentry el1_error_invalid

	vtentry el1_sync
	vtentry el1_irq
	vtentry el1_fiq_invalid
	vtentry el1_error_invalid

	vtentry el0_sync
	vtentry el0_irq
	vtentry el0_fiq_invalid
	vtentry el0_error_invalid

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
    MOV X0, SP
    CLREX
    RESTORE_CONTEXT

.align 3
el0_irq:
	SAVE_CONTEXT
	MOV X0, SP
	BL aarch64_do_irq
	B arch_context_switch_exit

.align 3
el1_sync:
	SAVE_CONTEXT
	MOV X0, SP
	BL trap_dispatch
	B arch_context_switch_exit

.align 3
el0_sync:
	SAVE_CONTEXT
	MOV X0, SP
    BL trap_dispatch
	B arch_context_switch_exit

.align 3
el1_irq:
	SAVE_CONTEXT
	MOV X0, SP
	BL aarch64_do_irq
	B arch_context_switch_exit

.global setup_vectors
setup_vectors:
    ldr x0, =vectors
	msr vbar_el1, x0
	isb

    mov x0, #0x00300000         /* Don't trap any SIMD/FP instructions in both EL0 and EL1 */
    msr cpacr_el1, x0

    ret
