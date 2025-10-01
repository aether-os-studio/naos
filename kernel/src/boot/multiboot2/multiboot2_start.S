.code32

# Multiboot2 头部
.section .multiboot, "a"
.align 8
multiboot_header:
    .long 0xE85250D6                # multiboot2 magic number
    .long 0                         # architecture (i386)
    .long multiboot_header_end - multiboot_header  # header length
    .long -(0xE85250D6 + 0 + (multiboot_header_end - multiboot_header))  # checksum

    # 结束标签
    .align 8
    .word 0                         # type: end
    .word 0                         # flags
    .long 8                         # size
multiboot_header_end:

# 启动代码段 - 在低地址
.section .boot, "a"
.align 4096

.global _mb2_start
.type _mb2_start, @function

_mb2_start:
    cli
    
    # 设置启动栈
    movl $boot_stack_top, %esp
    
    # 保存multiboot信息
    movl %eax, boot_multiboot_magic
    movl %ebx, boot_multiboot_info
    
    # 检查长模式支持
    call check_long_mode
    
    # 设置页表
    call setup_boot_page_tables
    
    # 启用PAE
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    
    # 设置页表基址
    movl $boot_pml4, %eax
    movl %eax, %cr3
    
    # 启用长模式
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x100, %eax
    wrmsr
    
    # 启用分页
    movl %cr0, %eax
    orl $0x80000000, %eax
    movl %eax, %cr0
    
    # 加载64位GDT
    lgdt gdt64_descriptor
    
    # 跳转到64位代码
    ljmp $0x08, $long_mode_start

check_long_mode:
    # 检查CPUID
    pushfl
    pop %eax
    mov %eax, %ecx
    xor $0x200000, %eax
    push %eax
    popfl
    pushfl
    pop %eax
    xor %ecx, %eax
    jz no_long_mode
    
    # 检查扩展功能
    mov $0x80000000, %eax
    cpuid
    cmp $0x80000001, %eax
    jb no_long_mode
    
    # 检查长模式位
    mov $0x80000001, %eax
    cpuid
    test $0x20000000, %edx
    jz no_long_mode
    ret

no_long_mode:
    hlt

# 设置启动页表
setup_boot_page_tables:
    # 清空所有页表
    movl $boot_pml4, %edi
    movl $0, %eax
    movl $(4096 * (1 + 3 + 3 + 64)) / 4, %ecx  # 所有页表的总大小
    rep stosl
    
    # 设置PML4
    # PML4[0] -> 低地址PDPT (0x0000000000000000)
    movl $boot_pml4, %eax
    movl $boot_pdpt_low, %ebx
    orl $0x3, %ebx
    movl %ebx, (%eax)
    
    # PML4[511] -> 高地址PDPT (0xFFFFFFFF80000000)
    movl $boot_pdpt_high, %ebx
    orl $0x3, %ebx
    movl %ebx, 511*8(%eax)
    
    # PML4[256] -> HHDM PDPT (0xFFFF800000000000)
    movl $boot_pdpt_hhdm, %ebx
    orl $0x3, %ebx
    movl %ebx, 256*8(%eax)
    
    # 设置低地址PDPT[0] -> 低地址PD
    movl $boot_pdpt_low, %eax
    movl $boot_pd_low, %ebx
    orl $0x3, %ebx
    movl %ebx, (%eax)
    
    # 设置高地址PDPT[510] -> 高地址PD (对应0xFFFFFFFF80000000)
    movl $boot_pdpt_high, %eax
    movl $boot_pd_high, %ebx
    orl $0x3, %ebx
    movl %ebx, 510*8(%eax)
    
    # 设置HHDM PDPT -> 多个PD (映射前128GB物理内存)
    movl $boot_pdpt_hhdm, %eax
    movl $boot_pd_hhdm, %ebx
    movl $64, %ecx                  # 64个PD条目，每个覆盖1GB
setup_hhdm_pdpt_loop:
    orl $0x3, %ebx
    movl %ebx, (%eax)
    addl $4096, %ebx
    andl $~0xFFF, %ebx
    addl $8, %eax
    loop setup_hhdm_pdpt_loop
    
    # 设置低地址PD - 映射前4MB
    movl $boot_pd_low, %eax
    movl $0x83, %ebx                # Present + Writable + PS (2MB)
    movl %ebx, (%eax)               # 0-2MB
    addl $0x200000, %ebx
    movl %ebx, 8(%eax)              # 2MB-4MB
    
    # 设置高地址PD - 映射内核 (假设内核在物理地址1MB开始，映射8MB)
    movl $boot_pd_high, %eax
    movl $0x100000, %ebx            # 内核物理起始地址 (1MB)
    orl $0x83, %ebx                 # Present + Writable + PS (2MB)
    movl $4, %ecx                   # 映射4个2MB页面 (8MB)
setup_kernel_pd_loop:
    movl %ebx, (%eax)
    addl $0x200000, %ebx            # 下一个2MB
    addl $8, %eax                   # 下一个PD条目
    loop setup_kernel_pd_loop
    
    # 设置HHDM PD - 映射前128GB物理内存
    movl $boot_pd_hhdm, %eax
    movl $0x0, %ebx                 # 物理地址从0开始
    movl $(64 * 512), %ecx          # 64个PD，每个512个条目
setup_hhdm_pd_loop:
    movl %ebx, %edx
    orl $0x83, %edx                 # Present + Writable + PS (2MB)
    movl %edx, (%eax)
    addl $0x200000, %ebx            # 下一个2MB
    addl $8, %eax                   # 下一个PD条目
    loop setup_hhdm_pd_loop
    
    ret

# 64位代码
.code64
long_mode_start:
    # 设置段寄存器
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    
    # 设置高地址栈
    movq $0xFFFFFFFF80000000, %rax
    addq $boot_stack_top, %rax
    subq $boot_stack_bottom, %rax
    movq %rax, %rsp
    
    movq boot_multiboot_magic, %rdi
    movq boot_multiboot_info, %rsi

    movq switch_to_setup_mappings(%rip), %rax
    pushq $0x08
    pushq %rax
    lretq

switch_to_setup_mappings:
    .quad setup_early_mappings

# 启动时使用的页表
boot_pml4:
    .skip 4096
boot_pdpt_low:
    .skip 4096
boot_pdpt_high:
    .skip 4096
boot_pdpt_hhdm:
    .skip 4096
boot_pd_low:
    .skip 4096
boot_pd_high:
    .skip 4096
boot_pd_hhdm:
    .skip 4096 * 64                # HHDM前128GB的页目录

# 启动栈
boot_stack_bottom:
    .skip 128 * 1024
boot_stack_top:

# 全局变量
boot_multiboot_magic:
    .long 0
boot_multiboot_info:
    .quad 0

# GDT
gdt64:
    .quad 0x0000000000000000        # null descriptor
    .quad 0x00AF9A000000FFFF        # 64-bit code segment
    .quad 0x00CF92000000FFFF        # 64-bit data segment
gdt64_end:

gdt64_descriptor:
    .word gdt64_end - gdt64 - 1
    .quad gdt64
