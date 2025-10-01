OUTPUT_FORMAT(elf64-x86-64)

ENTRY(_mb2_start)

SECTIONS {
    /* 内核物理加载地址 */
    . = 0x100000;

    /* 低地址部分 - 用于启动 */
	.boot : {
        KEEP(*(.multiboot))
        KEEP(*(.boot))
    }
    
    /* 内核虚拟地址 - 高半部分 */
    . += 0xffffffff80000000;
    
    kernel_virt_start = .;
    kernel_phys_start = . - 0xffffffff80000000;

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    
    .text : AT(ADDR(.text) - 0xffffffff80000000) {
        *(.text)
        *(.text.*)
    }
    
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : AT(ADDR(.rodata) - 0xffffffff80000000) {
        *(.rodata)
        *(.rodata.*)
    }

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .ksymtab : AT(ADDR(.ksymtab) - 0xffffffff80000000) {
        __ksymtab_start = .;
        KEEP(*(.ksymtab))
        __ksymtab_end = .;
    }

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : AT(ADDR(.data) - 0xffffffff80000000) {
        *(.data)
        *(.data.*)
    }
    
    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .bss : AT(ADDR(.bss) - 0xffffffff80000000) {
        *(.bss)
        *(.bss.*)
    }

    /* Discard .note.* and .eh_frame* since they may cause issues on some hosts. */
    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
    
    kernel_virt_end = .;
    kernel_phys_end = . - 0xffffffff80000000;
}
