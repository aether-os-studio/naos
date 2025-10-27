OUTPUT_FORMAT(elf64-x86-64)

ENTRY(_mb2_start)

SECTIONS {
    /* 内核物理加载地址 */
    . = 0x100000;

    /* 低地址部分 - 用于启动 */
	.boot : {
        KEEP(obj-x86_64/src/boot/x64/multiboot2/*(.multiboot))
        KEEP(obj-x86_64/src/boot/x64/multiboot2/*(.boot))
    }
    
    /* 内核虚拟地址 - 高半部分 */
    . += 0xffff800000000000;
    
    kernel_virt_start = .;
    kernel_phys_start = . - 0xffff800000000000;

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    
    .text : AT(ADDR(.text) - 0xffff800000000000) {
        *(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .text)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .text.*)
    }
    
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : AT(ADDR(.rodata) - 0xffff800000000000) {
        *(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .rodata)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .rodata.*)
    }

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .ksymtab : AT(ADDR(.ksymtab) - 0xffff800000000000) {
        __ksymtab_start = .;
        KEEP(*(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .ksymtab))
        __ksymtab_end = .;
    }

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : AT(ADDR(.data) - 0xffff800000000000) {
        *(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .data)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .data.*)
    }
    
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .bss : AT(ADDR(.bss) - 0xffff800000000000) {
        *(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .bss)
        *(EXCLUDE_FILE(obj-x86_64/src/boot/x64/multiboot2/*) .bss.*)
    }

    /* Discard .note.* and .eh_frame* since they may cause issues on some hosts. */
    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
    
    kernel_virt_end = .;
    kernel_phys_end = . - 0xffff800000000000;
}
