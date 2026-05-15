#include <settings.h>

.option norvc

.section .sbi_boot.text, "ax", @progbits
.global _sbi_start
.type _sbi_start, @function
_sbi_start:
    csrw sie, zero
    csrw satp, zero
    sfence.vma zero, zero

    lla t0, __sbi_boot_stack_top
    mv sp, t0

    lla t0, sbi_boot_hartid
    sd a0, 0(t0)
    lla t0, sbi_boot_dtb_phys
    sd a1, 0(t0)

    call __sbi_setup_page_tables

    lla t0, __sbi_root_pt
    srli t0, t0, 12
    li t1, 8
    slli t1, t1, 60
    or t0, t0, t1
    csrw satp, t0
    sfence.vma zero, zero

    lla t0, __sbi_boot_stack_top
    li t1, 0xffffffff80200000 - 0x80200000
    add t0, t0, t1
    mv sp, t0

    lla t0, 1f
    li t1, 0xffffffff80200000 - 0x80200000
    add t0, t0, t1
    jr t0

1:
    lla t0, __sbi_kmain_ptr
    ld t0, 0(t0)
    jalr t0

2:
    wfi
    j 2b

.type __sbi_setup_page_tables, @function
__sbi_setup_page_tables:
    lla t0, __sbi_root_pt
    li t1, 4096 * 259
    mv t2, t0
1:
    sd zero, 0(t2)
    addi t2, t2, 8
    addi t1, t1, -8
    bnez t1, 1b

    /* Root[510] -> high-half kernel subtree. */
    lla t0, __sbi_root_pt
    lla t1, __sbi_high_l1_pt
    srli t1, t1, 12
    slli t1, t1, 10
    ori t1, t1, 0x1
    li t2, 4080
    add t2, t0, t2
    sd t1, 0(t2)

    /* Root[2] -> low identity subtree while this boot code is running. */
    lla t1, __sbi_low_l1_pt
    srli t1, t1, 12
    slli t1, t1, 10
    ori t1, t1, 0x1
    sd t1, 16(t0)

    /* Map the boot page at VA 0x80200000 to PA 0x80200000. */
    lla t0, __sbi_low_l1_pt
    li t1, 0x80200000
    srli t1, t1, 12
    slli t1, t1, 10
    li t2, 0xcf
    or t1, t1, t2
    sd t1, 8(t0)

    /*
     * Map the whole high-half kernel window
     * 0xffffffff80000000..0xffffffffbfffffff
     * to PA 0x80000000..0xbfffffff using 2MiB pages.
     */
    lla t0, __sbi_high_l1_pt
    li t1, 0x80000000
    li t2, 0xcf
    li t3, 512
2:
    mv t4, t1
    srli t4, t4, 12
    slli t4, t4, 10
    or t4, t4, t2
    sd t4, 0(t0)
    addi t0, t0, 8
    li t4, 1 << 21
    add t1, t1, t4
    addi t3, t3, -1
    bnez t3, 2b

    /*
     * Early HHDM bootstrap:
     * map only the 2MiB page containing the DTB passed in a1.
     * boot_init() expands the rest from the DTB memory map.
     */
    lla t0, sbi_boot_dtb_phys
    ld t1, 0(t0)
    beqz t1, 2f

    li t2, 0xffffffc000000000
    add t2, t2, t1
    srli t3, t2, 30
    andi t3, t3, 511
    li t4, 256
    bltu t3, t4, 2f
    li t4, 510
    bgeu t3, t4, 2f

    lla t0, __sbi_root_pt
    lla t4, __sbi_hhdm_l1_pts
    addi t5, t3, -256
    slli t5, t5, 12
    add t4, t4, t5

    slli t5, t3, 3
    add t5, t0, t5
    srli t6, t4, 12
    slli t6, t6, 10
    ori t6, t6, 0x1
    sd t6, 0(t5)

    li t5, -1
    slli t5, t5, 21
    and t1, t1, t5
    srli t5, t1, 21
    andi t5, t5, 511
    slli t5, t5, 3
    add t4, t4, t5
    srli t1, t1, 12
    slli t1, t1, 10
    ori t1, t1, 0xc7
    sd t1, 0(t4)

    ret

.section .sbi_boot.data, "aw", @progbits
.global sbi_boot_hartid
sbi_boot_hartid:
    .quad 0

.global sbi_boot_dtb_phys
sbi_boot_dtb_phys:
    .quad 0

__sbi_kmain_ptr:
    .quad _start

.section .sbi_boot.bss, "aw", @nobits
.align 12
.global __sbi_root_pt
__sbi_root_pt:
    .skip 4096

.global __sbi_high_l1_pt
__sbi_high_l1_pt:
    .skip 4096

.global __sbi_low_l1_pt
__sbi_low_l1_pt:
    .skip 4096

.global __sbi_hhdm_l1_pts
__sbi_hhdm_l1_pts:
    .skip 4096 * 254

.align 12
__sbi_boot_stack:
    .skip STACK_SIZE
.global __sbi_boot_stack_top
__sbi_boot_stack_top:
