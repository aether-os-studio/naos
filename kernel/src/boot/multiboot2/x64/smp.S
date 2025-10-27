#include <arch/x64/asm.h>

.align 0x1000

.section .text
.code16

ENTRY(_apu_boot_start)
_apu_boot_base = .
    cli
    wbinvd

    mov %cs, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs

    mov %cs, %ax
    movzx %ax, %esi
    shll $4, %esi

    leal (_apu_code32 - _apu_boot_base)(%esi), %eax
    movl %eax, (_apu_code32_vector - _apu_boot_base)

    leal (_apu_code64 - _apu_boot_base)(%esi), %eax
    movl %eax, (_apu_code64_vector - _apu_boot_base)

    leal (_apu_tmp_gdt - _apu_boot_base)(%esi), %eax
    movl %eax, (_apu_tmp_gdt + 2 - _apu_boot_base)
    
    lidtl _apu_tmp_idt - _apu_boot_base
    lgdtl _apu_tmp_gdt - _apu_boot_base

    smsw %ax
    bts $0, %ax
    lmsw %ax

    ljmpl *(_apu_code32_vector - _apu_boot_base)

.code32
.align 0x1000 
_apu_code32:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs

    movl %eax, %esp

    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4

    movl $enter_head_from_ap_boot, %eax
    jmpl *%eax
    hlt

.code64
.align 0x1000 
_apu_code64:
    hlt

.align 0x1000 
_apu_tmp_idt:
	.word	0
	.word	0,0

.align 0x1000 
_apu_tmp_gdt:
    .short _apu_tmp_gdt_end - _apu_tmp_gdt -1
    .long _apu_tmp_gdt - _apu_boot_base
    .short 0
    .quad	0x00cf9a000000ffff
	.quad	0x00cf92000000ffff
_apu_tmp_gdt_end:

.align 0x1000 
_apu_code32_vector:
	.long	_apu_code32 - _apu_boot_base
	.word	0x08,0	

.align 0x1000 
_apu_code64_vector:
	.long	_apu_code64 - _apu_boot_base
	.word	0x18,0	

ENTRY(_apu_boot_end)
