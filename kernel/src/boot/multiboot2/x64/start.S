#include <settings.h>
#include <boot/multiboot2/x64/multiboot2.h>

.code32

.section .multiboot, "a"
multiboot_header:
.align 8
    .long MULTIBOOT2_HEADER_MAGIC
    .long MULTIBOOT_ARCHITECTURE_I386
    .long multiboot_header_end - multiboot_header
    .long -(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT_ARCHITECTURE_I386 + (multiboot_header_end - multiboot_header))

.align 8
entry_address_tag_start:    
        .short MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS
        .short MULTIBOOT_HEADER_TAG_OPTIONAL
        .long entry_address_tag_end - entry_address_tag_start
        .long _mb2_start
entry_address_tag_end:

.align 8
framebuffer_tag_start:
    .short MULTIBOOT_HEADER_TAG_FRAMEBUFFER
    .short MULTIBOOT_HEADER_TAG_OPTIONAL
    .long framebuffer_tag_end - framebuffer_tag_start
    .long 1280
    .long 800
    .long 32
framebuffer_tag_end:

.align 8
    .short MULTIBOOT_HEADER_TAG_END
    .short 0
    .long 8
multiboot_header_end:

.section .boot, "ax"

.code32
.align 0x1000
pml4:
    .skip 0x1000
pdpt:
    .skip 0x1000
pd:
    .skip 0x1000
pt:
    .skip 0x1000

.align 16
gdt64:
null_desc:
    .short 0xFFFF
    .short 0
    .byte 0
    .byte 0
    .byte 0
    .byte 0
code_desc:
    .short 0
    .short 0
    .byte 0
    .byte 0x9A
    .byte 0x20
    .byte 0
data_desc:
    .short 0
    .short 0
    .byte 0
    .byte 0x92
    .byte 0
    .byte 0
user_code_desc:
    .short 0
    .short 0
    .byte 0
    .byte 0xFA
    .byte 0x20
    .byte 0
user_data_desc:
    .short 0
    .short 0
    .byte 0
    .byte 0xF2
    .byte 0
    .byte 0
gdt64_pointer:
    .short gdt64_pointer-gdt64-1
    .quad gdt64
gdt64_pointer64:
    .short gdt64_pointer-gdt64-1
    .quad gdt64

_mb2_magic:
    .quad 0
_mb2_addr:
    .quad 0

_boot_stack_start:
    .skip 32768, 0
_boot_stack_end:

.global _mb2_start
_mb2_start:
    movl %eax, _mb2_magic
    movl %ebx, _mb2_addr

    movl $_boot_stack_end, %esp

    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4

    mov $pml4, %eax
    mov $pdpt, %ebx
    or $0x3, %ebx
    mov %ebx, 0(%eax)

    mov $pdpt, %eax
    mov $pd, %ebx
    or $0x3, %ebx
    mov %ebx, 0(%eax)

    mov $pd, %eax
    mov $pt, %ebx
    or $0x3, %ebx
    mov %ebx, 0(%eax)

    mov $512, %ecx
    mov $pt, %eax
    mov $0x3, %ebx
.fill_pt:
    mov %ebx, 0(%eax)
    add $0x1000, %ebx
    add $8, %eax
    loop .fill_pt

.global enter_head_from_ap_boot
enter_head_from_ap_boot:
    mov $pml4, %eax
    mov %eax, %cr3

    mov $0xC0000080, %ecx
    rdmsr
    or $(1 << 8), %eax
    wrmsr

    mov %cr0, %eax
    or $(1 << 31), %eax
    mov %eax, %cr0

    mov $gdt64_pointer, %eax
    lgdt 0(%eax)

    jmp $0x8, $ready_to_start_64

.code64
ready_to_start_64:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %ss

    movq switch_to_start64(%rip), %rax
    pushq $0x08
    pushq %rax
    lretq

switch_to_start64:
    .quad _start64

_start64:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %ss

    movq $0x1b, %rcx
	rdmsr
	bt	$8,	%rax
	jnc	load_cr3

    mov $__PML4E, %eax
    mov $__PDPTE, %ebx
    or $0x3, %ebx
    mov %ebx, 0(%eax)

    mov $__PML4E, %eax
    add $2048, %eax
    mov %ebx, 0(%eax)

    mov $__PDPTE, %eax
    mov $__PDE, %ebx
    or $0x3, %ebx
    mov %ebx, 0(%eax)

    mov $__PDE, %eax
    mov $50, %ecx
    mov $__PT_S, %ebx
    or $0x3, %ebx
.fill_pde_64:
    mov %ebx, 0(%eax)
    add $0x1000, %ebx
    add $8, %eax
    loop .fill_pde_64

    mov $25600, %ecx
    mov $__PT_S, %eax
    mov $0x3, %ebx
.fill_pt_64:
    mov %ebx, 0(%eax)
    add $0x1000, %ebx
    add $8, %eax
    loop .fill_pt_64

load_cr3:
    movq $__PML4E, %rax
    movq %rax, %cr3
    
    movq switch_to_entry64(%rip), %rax

    pushq $0x08
    pushq %rax

    lretq

switch_to_entry64:
    .quad entry64

entry64:
    movq $0x10, %rax
    movq %rax, %ds
    movq %rax, %es
    movq %rax, %gs
    movq %rax, %ss

    lgdt BOOT_GDT_POINTER64(%rip)

    movq $0x1b, %rcx
    rdmsr
	bt $8, %rax
	jnc entry64_smp

    movq $_kernel_stack_end, %rax
    movq $0xffff800000000000, %rbx
    addq %rbx, %rax
    movq %rax, %rbp
    movq %rax, %rsp

    movq _mb2_magic, %rdi
    movq _mb2_addr, %rsi

    movq switch_to_c_start(%rip), %rax

    pushq $0x08
    pushq %rax

    lretq

switch_to_c_start:
    .quad multiboot2_c_start

entry64_smp:
    movq $_apu_tmp_stack_end, %rax
    movq $0xffff800000000000, %rbx
    addq %rbx, %rax
    movq %rax, %rbp
    movq %rax, %rsp

    movq switch_to_c_ap_entry(%rip), %rax

    pushq $0x08
    pushq %rax

    lretq

switch_to_c_ap_entry:
    .quad multiboot2_ap_entry

.align 16
_kernel_stack_start:
    .skip STACK_SIZE, 0
_kernel_stack_end:

.align 16
_apu_tmp_stack_start:
    .skip STACK_SIZE, 0
_apu_tmp_stack_end:

.align 16
.global BOOT_GDT_Table

BOOT_GDT_Table:
    .quad 0x0000000000000000 // 0 空描述符 0x00
    .quad 0x0020980000000000 // 1 内核64位代码段描述符 0x08
    .quad 0x0000920000000000 // 2 内核64位数据段描述符 0x10
    .quad 0x0000000000000000 // 3 用户32位代码段描述符 0x18
    .quad 0x0000000000000000 // 4 用户32位数据段描述符 0x20
    .quad 0x00cff3000000ffff // 5 用户64位数据段描述符 0x28
    .quad 0x00affb000000ffff // 6 用户64位代码段描述符 0x30
    .quad 0x00cf9a000000ffff // 7 内核32位代码段描述符 0x38
    .quad 0x00cf92000000ffff // 8 内核32位数据段描述符 0x40
    .fill 1, 8, 0
BOOT_GDT_END:

.global BOOT_GDT_POINTER
BOOT_GDT_POINTER:
BOOT_GDT_LIMIT: .word BOOT_GDT_END - BOOT_GDT_Table - 1
BOOT_GDT_BASE: .quad BOOT_GDT_Table

.global BOOT_GDT_POINTER64
BOOT_GDT_POINTER64:
BOOT_GDT_LIMIT64: .word BOOT_GDT_END - BOOT_GDT_Table - 1
BOOT_GDT_BASE64: .quad BOOT_GDT_Table + 0xffff800000000000

.align 0x1000
__PML4E:
    .skip 0x1000
__PDPTE:
	.skip 0x1000
__PDE:
    .skip 0x1000
__PT_S:
    .skip 0x32000
