OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_mb2_start)

SECTIONS {
    KERNEL_VMA = 0xffff800000000000;
    /* 内核物理加载地址 */
    . = 0x100000;

    /* 低地址部分 - 用于启动 */
	.bootstrap : {
        KEEP(obj-x86_64/src/boot/multiboot2/x64/*(.multiboot))
        KEEP(obj-x86_64/src/boot/multiboot2/x64/*(.boot))
    }
    
    /* 内核虚拟地址 - 高半部分 */
    . += KERNEL_VMA;
    
    kernel_virt_start = .;
    kernel_phys_start = . - KERNEL_VMA;

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    
    text_start_va = .;
    .text (text_start_va) : AT(text_start_va - KERNEL_VMA) {
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .text)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .text.*)
    }
    
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    rodata_start_va = .;
    .rodata (rodata_start_va) : AT(rodata_start_va - KERNEL_VMA) {
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .rodata)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .rodata.*)
    }

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    ksymtab_start_va = .;
    .ksymtab (ksymtab_start_va) : AT(ksymtab_start_va - KERNEL_VMA) {
        __ksymtab_start = .;
        KEEP(*(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .ksymtab))
        __ksymtab_end = .;
    }

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    data_start_va = .;
    .data (data_start_va) : AT(data_start_va - KERNEL_VMA) {
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .data)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .data.*)
    }
    
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    bss_start_va = .;
    .bss (bss_start_va) : AT(bss_start_va - KERNEL_VMA) {
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .bss)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) .bss.*)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/multiboot2/x64/*) COMMON)
    }

    /* Discard .note.* and .eh_frame* since they may cause issues on some hosts. */
    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
    
    kernel_virt_end = .;
    kernel_phys_end = . - KERNEL_VMA;
}
