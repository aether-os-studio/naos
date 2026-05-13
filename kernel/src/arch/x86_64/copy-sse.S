.section .text
.global fast_copy_16

fast_copy_16:
    testq   %rdx, %rdx
    jz      .end
    
    cmpq    $16, %rdx
    jb      .tail_copy
    
    movq    %rdx, %rcx
    shrq    $4, %rcx
    andq    $0x0F, %rdx

.loop:
    movdqu  (%rsi), %xmm0
    movdqu  %xmm0, (%rdi) 
    addq    $16, %rsi
    addq    $16, %rdi
    decq    %rcx
    jnz     .loop
    
    testq   %rdx, %rdx
    jz      .end 

.tail_copy:
    testb   $8, %dl
    jz      .lt8
    movq    (%rsi), %rax
    movq    %rax, (%rdi)
    addq    $8, %rsi
    addq    $8, %rdi

.lt8:
    testb   $4, %dl
    jz      .lt4
    movl    (%rsi), %eax
    movl    %eax, (%rdi)
    addq    $4, %rsi
    addq    $4, %rdi

.lt4:
    testb   $2, %dl
    jz      .lt2
    movw    (%rsi), %ax
    movw    %ax, (%rdi)
    addq    $2, %rsi
    addq    $2, %rdi

.lt2:
    testb   $1, %dl
    jz      .end
    movb    (%rsi), %al
    movb    %al, (%rdi)

.end:
    retq
