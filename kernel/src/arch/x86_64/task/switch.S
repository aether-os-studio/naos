#include "arch/x86_64/asm.h"

CTX_RSP = 0x00

.section .text

ENTRY(x86_64_switch_to)
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rsp, CTX_RSP(%rdi)
    movq CTX_RSP(%rsi), %rsp

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp

    movq %rdx, %rdi
    movq %rcx, %rsi
    jmp __switch_to
