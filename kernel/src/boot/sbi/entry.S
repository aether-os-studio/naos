.section .boot

.global open_sbi_start
open_sbi_start:
    # set stack
    # sp = bootstack + (hartid + 1) * 0x10000
    add     t0, a0, 1
    slli    t0, t0, 14
    lui     sp, %hi(bootstack)
    add     sp, sp, t0

    # enable paging
    # satp = (8 << 60) | PPN(boot_page_table_sv39)
    lui     t0, %hi(boot_page_table_sv39)
    li      t1, 0xffffffff80000000 - 0x80000000
    sub     t0, t0, t1
    srli    t0, t0, 12
    li      t1, 8 << 60
    or      t0, t0, t1
    csrw    satp, t0
    sfence.vma

    # jump C sbi_main
    lui     t0, %hi(sbi_main)
    addi    t0, t0, %lo(sbi_main)
    jr      t0
    wfi

    .section .bss.stack
    .align 12   # page align
    .global bootstack
bootstack:
    .space 4096 * 4 * 8
    .global bootstacktop
bootstacktop:

    .section .data
    .align 12   # page align
boot_page_table_sv39:
    # 0x00000000_80000000 -> 0x80000000 (1G)
    # 0xffffffff_80000000 -> 0x80000000 (1G)
    .quad 0
    .quad 0
    .quad (0x80000 << 10) | 0xcf # VRWXAD
    .zero 8 * 507
    .quad (0x80000 << 10) | 0xcf # VRWXAD
    .quad 0
