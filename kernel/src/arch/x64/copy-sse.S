.section .text
.global fast_copy_16

fast_copy_16:
    # 参数: %rdi = dest, %rsi = src, %rdx = n
    testq   %rdx, %rdx        # 检查 n 是否为 0
    jz      .end              # 如果 n=0，直接返回
    
    # 处理小数据块（n < 16）
    cmpq    $16, %rdx
    jb      .tail_copy        # 跳转到尾部复制（处理 <16 字节）
    
    # 准备循环：复制 16 字节块
    movq    %rdx, %rcx        # rcx = n
    shrq    $4, %rcx          # rcx = n / 16（循环次数）
    andq    $0x0F, %rdx       # rdx = n % 16（剩余字节）

.loop:
    movdqu  (%rsi), %xmm0     # 从 src 加载 16 字节（非对齐）
    movdqu  %xmm0, (%rdi)     # 存储到 dest（非对齐）
    addq    $16, %rsi
    addq    $16, %rdi
    decq    %rcx
    jnz     .loop             # 循环直到所有块复制完毕
    
    # 检查是否有剩余字节（0-15）
    testq   %rdx, %rdx
    jz      .end              # 无剩余则结束

.tail_copy:
    # 复制剩余字节（1-15），按 8/4/2/1 字节分段处理
    testb   $8, %dl           # 检查是否需复制 8 字节
    jz      .lt8
    movq    (%rsi), %rax      # 复制 8 字节
    movq    %rax, (%rdi)
    addq    $8, %rsi
    addq    $8, %rdi

.lt8:
    testb   $4, %dl           # 检查是否需复制 4 字节
    jz      .lt4
    movl    (%rsi), %eax      # 复制 4 字节
    movl    %eax, (%rdi)
    addq    $4, %rsi
    addq    $4, %rdi

.lt4:
    testb   $2, %dl           # 检查是否需复制 2 字节
    jz      .lt2
    movw    (%rsi), %ax       # 复制 2 字节
    movw    %ax, (%rdi)
    addq    $2, %rsi
    addq    $2, %rdi

.lt2:
    testb   $1, %dl           # 检查是否需复制 1 字节
    jz      .end
    movb    (%rsi), %al       # 复制 1 字节
    movb    %al, (%rdi)

.end:
    retq                      # 函数返回
