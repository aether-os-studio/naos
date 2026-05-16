OUTPUT_FORMAT(elf64-loongarch)
ENTRY(_start)

KERNEL_PHYS_BASE = 0x00300000;
KERNEL_VIRT_BASE = 0xffffffff80000000 + KERNEL_PHYS_BASE;
KERNEL_VIRT_OFFSET = KERNEL_VIRT_BASE - KERNEL_PHYS_BASE;

PHDRS
{
    boot PT_LOAD FLAGS(7);
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = KERNEL_PHYS_BASE;
    __kernel_phys_start = .;
    __boot_start = .;

    .boot : {
        KEEP(*(.boot.entry))
        KEEP(*(.boot.text .boot.text.*))
        KEEP(*(.boot.rodata .boot.rodata.*))
        KEEP(*(.boot.data .boot.data.*))
    } :boot

    . = ALIGN(0x1000);
    .boot.bss (NOLOAD) : {
        __boot_bss_start = .;
        KEEP(*(.boot.bss .boot.bss.*))
        __boot_bss_end = .;
    } :boot

    . = ALIGN(0x1000);
    __boot_end = .;

    . += KERNEL_VIRT_OFFSET;
    __kernel_virt_start = .;

    .text : AT(ADDR(.text) - KERNEL_VIRT_OFFSET) {
        _text = .;
        *(.text .text.*)
        _etext = .;
    } :text

    . = ALIGN(0x1000);
    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT_OFFSET) {
        *(.srodata .srodata.*)
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(0x1000);
    .data : AT(ADDR(.data) - KERNEL_VIRT_OFFSET) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } :data

    . = ALIGN(0x1000);
    .bss : AT(ADDR(.bss) - KERNEL_VIRT_OFFSET) {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    . = ALIGN(0x1000);
    __kernel_image_end = .;
    __kernel_virt_end = .;
    __kernel_phys_end = __kernel_virt_end - KERNEL_VIRT_OFFSET;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
    }
}
