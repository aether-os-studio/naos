#include "arch/x64/asm.h"
#include "settings.h"

ENTRY(syscall_exception)
    cli

    swapgs

    movq %rsp, %gs:0x8 // syscall_stack_user

    cmpq $0, %gs:0x20 // call_in_signal
    je normal

signal:
    movq %gs:0x10, %rsp // signal_syscall_stack
    jmp next

normal:
    movq %gs:0x0, %rsp // syscall_stack

next:
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

    movq %rsp, %rdi
    movq %gs:0x8, %rsi

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
    movq %rax, %ds
    popq %rax
    movq %rax, %es

    popq %rax

    addq $0x28, %rsp

    popq %rsp

    sysretq
