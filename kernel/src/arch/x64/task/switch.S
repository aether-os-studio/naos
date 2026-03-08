#include "arch/x64/asm.h"

#define ARCH_CTX_RIP 0x00
#define ARCH_CTX_RSP 0x08

.section .text

ENTRY(arch_context_switch)
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %rax

    movq %rdx, %r12
    movq %rcx, %r13

    movq %rsp, ARCH_CTX_RSP(%r12)
    leaq .Lrestore_context(%rip), %rax
    movq %rax, ARCH_CTX_RIP(%r12)

    call __switch_to

    movq ARCH_CTX_RSP(%r13), %rsp
    jmp *ARCH_CTX_RIP(%r13)

.Lrestore_context:
    popq %rax
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    ret
