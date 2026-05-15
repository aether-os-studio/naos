OUTPUT_FORMAT(elf64-littleriscv)
ENTRY(_sbi_start)

KERNEL_PHYS_BASE = 0x80200000;
KERNEL_VIRT_BASE = 0xffffffff80200000;
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

    __sbi_boot_start = .;
    .sbi_boot : {
        KEEP(*(.sbi_boot .sbi_boot.*))
    } :boot

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __sbi_boot_end = .;
    __sbi_boot_start_virt = __sbi_boot_start + KERNEL_VIRT_OFFSET;
    __sbi_boot_end_virt = __sbi_boot_end + KERNEL_VIRT_OFFSET;
    __sbi_boot_hartid_virt = sbi_boot_hartid + KERNEL_VIRT_OFFSET;
    __sbi_boot_dtb_phys_virt = sbi_boot_dtb_phys + KERNEL_VIRT_OFFSET;
    __sbi_root_pt_virt = __sbi_root_pt + KERNEL_VIRT_OFFSET;
    __sbi_hhdm_l1_pts_virt = __sbi_hhdm_l1_pts + KERNEL_VIRT_OFFSET;

    . += KERNEL_VIRT_OFFSET;
    __kernel_image_start = KERNEL_VIRT_BASE;

    .text : AT(ADDR(.text) - KERNEL_VIRT_OFFSET) {
        _text = .;
        *(.text .text.*)
        _etext = .;
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT_OFFSET) {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : AT(ADDR(.data) - KERNEL_VIRT_OFFSET) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } :data

    .bss : AT(ADDR(.bss) - KERNEL_VIRT_OFFSET) {
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
    } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .initramfs : AT(ADDR(.initramfs) - KERNEL_VIRT_OFFSET) {
        __initramfs_start = .;
        *(.initramfs)
        __initramfs_end = .;
    } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __kernel_image_end = .;

    __kernel_phys_start = __kernel_image_start - KERNEL_VIRT_OFFSET;
    __kernel_phys_end = __kernel_image_end - KERNEL_VIRT_OFFSET;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
