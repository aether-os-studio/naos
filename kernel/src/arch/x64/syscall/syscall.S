#include "arch/x64/asm.h"
#include "settings.h"

ENTRY(syscall_exception)
    cli

    swapgs

    movq %rsp, %cr2

    movq %gs:0x0, %rsp // syscall_stack

    subq $0x38, %rsp

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

    movq %rsp, %rdi
    movq %cr2, %rsi

    swapgs

    call syscall_handler

ENTRY(ret_from_syscall)
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

    addq $0x28, %rsp

    popq %rsp

    sysretq
