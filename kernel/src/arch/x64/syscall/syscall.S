#include "arch/x64/asm.h"
#include "settings.h"

ENTRY(syscall_exception)
    cli
    cld

    subq $0x38, %rsp

    pushq %rax

    movq %es, %rax
    pushq %rax
    movq %ds, %rax
    pushq %rax

    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rsp, %r15

    call switch_to_kernel_stack
    subq $0xc0, %rax
    movq %rax, %rsp

    movq %rsp, %rdi
    movq %r15, %rsi
    movq $0xc0, %rdx
    call real_memcpy

    movq %rsp, %rdi
    movq %r15, %rsi
    call syscall_handler

    movq %r15, %rdi
    movq %rsp, %rsi
    movq $0xc0, %rdx
    call real_memcpy

    movq %rax, %rsp

ret_from_syscall:
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
    movq %rax, %ds
    popq %rax
    movq %rax, %es

    popq %rax

    addq $0x38, %rsp

    sysretq
