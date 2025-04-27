.section .text

.global restorer

#if defined(__x86_64__)

restorer:
    endbr64

    addq $0x8, %rsp
    movq -0x8(%rsp), %rdi
    call ssetmask
    addq $0x8, %rsp

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

    ret

#endif
