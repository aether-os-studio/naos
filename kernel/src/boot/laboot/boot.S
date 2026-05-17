#define KERNEL_PHYS_BASE 0x00300000
#define KERNEL_VIRT_BASE 0xffffffff80300000

#define CPUCFG_ADDR_WIDTH 0x1
#define CSR_CRMD        0x0
#define CSR_PGDL        0x19
#define CSR_PGDH        0x1a
#define CSR_PGD         0x1b
#define CSR_PWCTL0      0x1c
#define CSR_PWCTL1      0x1d
#define CSR_STLBPGSIZE  0x1e
#define CSR_CPUID       0x20
#define CSR_DMWIN0      0x180
#define CSR_DMWIN1      0x181
#define CSR_DMWIN2      0x182
#define CSR_DMWIN3      0x183
#define CSR_TLBRENTRY   0x88
#define CSR_TLBRSAVE    0x8b

#define CRMD_PG         (1 << 4)
#define CRMD_DA         (1 << 3)
#define CRMD_IE         (1 << 2)

#define DMW_PLV0        (1 << 0)
#define DMW_MAT_CC      (1 << 4)
#define DMW0_BASE       0x8000000000000000
#define DMW0_CONFIG     (DMW0_BASE | DMW_MAT_CC | DMW_PLV0)

#define PAGE_PRESENT    (1 << 7)
#define PAGE_GLOBAL     (1 << 6)
#define PAGE_CACHE_CC   (1 << 4)
#define PAGE_MODIFIED   (1 << 9)
#define PAGE_WRITE      (1 << 8)
#define PAGE_DIRTY      (1 << 1)
#define PAGE_VALID      (1 << 0)

#define PTE_FLAGS       (PAGE_PRESENT | PAGE_GLOBAL | PAGE_CACHE_CC | PAGE_MODIFIED | PAGE_WRITE | PAGE_DIRTY | PAGE_VALID)

/* 4KiB pages, 9-bit page-table indices: 12, 21, 30, 39. */
#define PWCTL0_4LEVEL   ((9 << 25) | (30 << 20) | (9 << 15) | (21 << 10) | (9 << 5) | 12)
#define PWCTL1_4LEVEL   (39 | (9 << 6))

#define ROOT_HIGH_INDEX 511
#define KERNEL_L2_INDEX 510
#define HHDM_L2_TABLE_COUNT 254
#define BOOT_MAP_SIZE   0x08000000
#define BOOT_L3_COUNT   (BOOT_MAP_SIZE >> 21)
#define BOOT_PTE_COUNT  (BOOT_MAP_SIZE >> 12)
#define STACK_SIZE      16384

.macro load_abs reg, sym
    la.abs \reg, \sym
.endm

.macro phys_to_hhdm reg
    load_abs $t8, boot_info
    ld.d $t8, $t8, 24
    add.d \reg, \reg, $t8
.endm

.section .boot.entry, "ax", @progbits
.global _start
.type _start, @function
_start:
    move $s1, $a0
    move $s2, $a1
    move $s3, $a2

    load_abs $t0, boot_info

    csrrd $t1, CSR_CPUID
    st.d $t1, $t0, 0

    bl boot_detect_hhdm_base
    load_abs $t0, boot_info

    st.d $zero, $t0, 8
    st.d $zero, $t0, 16

    li.d $t1, KERNEL_PHYS_BASE
    st.d $t1, $t0, 32
    li.d $t1, KERNEL_VIRT_BASE
    st.d $t1, $t0, 40
    load_abs $t1, __kernel_phys_end
    st.d $t1, $t0, 48
    load_abs $t1, __kernel_virt_end
    st.d $t1, $t0, 56
    load_abs $t1, boot_root_pt
    st.d $t1, $t0, 64
    move $t2, $t1
    phys_to_hhdm $t2
    st.d $t2, $t0, 72
    st.d $s2, $t0, 80
    st.d $s3, $t0, 88
    move $t2, $s2
    phys_to_hhdm $t2
    st.d $t2, $t0, 96
    move $t2, $s3
    phys_to_hhdm $t2
    st.d $t2, $t0, 104

    bl boot_clear_boot_bss
    bl boot_setup_page_tables
    bl boot_enable_paging

    load_abs $sp, boot_stack_top
    phys_to_hhdm $sp

    load_abs $t0, high_entry
    jr $t0

.section .boot.text, "ax", @progbits
.type boot_detect_hhdm_base, @function
boot_detect_hhdm_base:
    li.w $t0, CPUCFG_ADDR_WIDTH
    cpucfg $t0, $t0
    srli.d $t0, $t0, 4
    andi $t0, $t0, 0xff
    addi.d $t0, $t0, 1
    li.w $t1, 39
    bgeu $t0, $t1, 1f
    move $t0, $t1
1:
    addi.d $t0, $t0, -1
    li.d $t1, 1
    sll.d $t1, $t1, $t0
    sub.d $t1, $zero, $t1
    load_abs $t2, boot_info
    st.d $t1, $t2, 24
    jr $ra

.type boot_clear_boot_bss, @function
boot_clear_boot_bss:
    load_abs $t0, __boot_bss_start
    load_abs $t1, __boot_bss_end
1:
    beq $t0, $t1, 2f
    st.d $zero, $t0, 0
    addi.d $t0, $t0, 8
    b 1b
2:
    jr $ra

.type boot_setup_page_tables, @function
boot_setup_page_tables:
    move $s0, $ra

    load_abs $a0, boot_pt_begin
    load_abs $a1, boot_pt_end
    bl boot_zero_range

    /* Root[0] -> low identity map for the transition path. */
    load_abs $t0, boot_root_pt
    load_abs $t1, boot_low_l2_pt
    st.d $t1, $t0, 0

    /* Root[511] -> kernel high-half subtree. */
    load_abs $t1, boot_high_l2_pt
    li.w $t2, ROOT_HIGH_INDEX * 8
    add.d $t3, $t0, $t2
    st.d $t1, $t3, 0

    /* Root[hhdm] -> the same subtree when VA width places HHDM elsewhere. */
    load_abs $t4, boot_info
    ld.d $t4, $t4, 24
    srli.d $t4, $t4, 39
    andi $t4, $t4, 511
    li.w $t2, ROOT_HIGH_INDEX
    beq $t4, $t2, 1f
    slli.d $t4, $t4, 3
    add.d $t3, $t0, $t4
    st.d $t1, $t3, 0
1:

    /* Low identity: VA 0..128MiB -> PA 0..128MiB. */
    load_abs $t0, boot_low_l2_pt
    load_abs $t1, boot_low_l3_pt
    st.d $t1, $t0, 0

    /* HHDM: VA hhdm_base..+128MiB -> PA 0..128MiB. */
    load_abs $t0, boot_high_l2_pt
    load_abs $t1, boot_hhdm_l3_pt
    load_abs $t2, boot_info
    ld.d $t2, $t2, 24
    srli.d $t2, $t2, 30
    andi $t2, $t2, 511
    slli.d $t2, $t2, 3
    add.d $t3, $t0, $t2
    st.d $t1, $t3, 0

    /*
     * Kernel high half: VA 0xffffffff80000000..+128MiB -> PA 0..128MiB.
     * KERNEL_VIRT_BASE is inside this window at +KERNEL_PHYS_BASE.
     */
    load_abs $t1, boot_kernel_l3_pt
    li.w $t2, KERNEL_L2_INDEX * 8
    add.d $t3, $t0, $t2
    st.d $t1, $t3, 0

    load_abs $a0, boot_low_l3_pt
    load_abs $a1, boot_low_pt_pages
    li.w $a2, BOOT_L3_COUNT
    bl boot_link_l3_to_pt_pages

    load_abs $a0, boot_hhdm_l3_pt
    load_abs $a1, boot_hhdm_pt_pages
    li.w $a2, BOOT_L3_COUNT
    bl boot_link_l3_to_pt_pages

    load_abs $a0, boot_kernel_l3_pt
    load_abs $a1, boot_kernel_pt_pages
    li.w $a2, BOOT_L3_COUNT
    bl boot_link_l3_to_pt_pages

    load_abs $a0, boot_low_pt_pages
    move $a1, $zero
    li.w $a2, BOOT_PTE_COUNT
    bl boot_fill_4k_ptes

    load_abs $a0, boot_hhdm_pt_pages
    move $a1, $zero
    li.w $a2, BOOT_PTE_COUNT
    bl boot_fill_4k_ptes

    load_abs $a0, boot_kernel_pt_pages
    move $a1, $zero
    li.w $a2, BOOT_PTE_COUNT
    bl boot_fill_4k_ptes

    load_abs $a0, boot_info
    ld.d $a1, $a0, 80
    bl boot_map_early_hhdm_pointer
    load_abs $a0, boot_info
    ld.d $a1, $a0, 88
    bl boot_map_early_hhdm_pointer

    jr $s0

.type boot_zero_range, @function
boot_zero_range:
1:
    beq $a0, $a1, 2f
    st.d $zero, $a0, 0
    addi.d $a0, $a0, 8
    b 1b
2:
    jr $ra

.type boot_link_l3_to_pt_pages, @function
boot_link_l3_to_pt_pages:
    li.w $t0, 4096
1:
    st.d $a1, $a0, 0
    addi.d $a0, $a0, 8
    add.d $a1, $a1, $t0
    addi.d $a2, $a2, -1
    bnez $a2, 1b
    jr $ra

.type boot_fill_4k_ptes, @function
boot_fill_4k_ptes:
    li.d $t0, PTE_FLAGS
    li.w $t1, 4096
1:
    move $t2, $a1
    or $t2, $t2, $t0
    st.d $t2, $a0, 0
    addi.d $a0, $a0, 8
    add.d $a1, $a1, $t1
    addi.d $a2, $a2, -1
    bnez $a2, 1b
    jr $ra

.type boot_map_early_hhdm_pointer, @function
boot_map_early_hhdm_pointer:
    beqz $a1, 3f
    li.d $t0, -2097152
    and $t1, $a1, $t0
    load_abs $t2, boot_info
    ld.d $t3, $t2, 24
    add.d $t3, $t3, $t1
    srli.d $t4, $t3, 30
    andi $t4, $t4, 511
    ld.d $t5, $t2, 24
    srli.d $t5, $t5, 30
    andi $t5, $t5, 511
    sub.d $t6, $t4, $t5
    li.w $t7, HHDM_L2_TABLE_COUNT
    bgeu $t6, $t7, 3f

    load_abs $t7, boot_hhdm_l3_pt
    slli.d $t6, $t6, 12
    add.d $t7, $t7, $t6
    load_abs $t6, boot_high_l2_pt
    slli.d $t4, $t4, 3
    add.d $t6, $t6, $t4
    st.d $t7, $t6, 0

    srli.d $t4, $t3, 21
    andi $t4, $t4, 511
    load_abs $t5, boot_hhdm_pt_pages
    slli.d $t4, $t4, 3
    add.d $t5, $t7, $t4

    li.d $t6, PTE_FLAGS
    or $t1, $t1, $t6
    st.d $t1, $t5, 0
3:
    jr $ra

.type boot_enable_paging, @function
boot_enable_paging:
    move $s0, $ra

    li.d $t0, PWCTL0_4LEVEL
    csrwr $t0, CSR_PWCTL0
    li.d $t0, PWCTL1_4LEVEL
    csrwr $t0, CSR_PWCTL1
    li.w $t0, 12
    csrwr $t0, CSR_STLBPGSIZE

    load_abs $t0, boot_root_pt
    move $t1, $t0
    csrwr $t0, CSR_PGDL
    csrwr $t1, CSR_PGDH
    invtlb 0, $zero, $zero

    li.d $t0, DMW0_CONFIG
    csrwr $t0, CSR_DMWIN0
    csrwr $zero, CSR_DMWIN1
    csrwr $zero, CSR_DMWIN2
    csrwr $zero, CSR_DMWIN3

    load_abs $t0, boot_tlb_refill
    li.d $t1, DMW0_BASE
    or $t0, $t0, $t1
    csrwr $t0, CSR_TLBRENTRY

    li.w $t0, CRMD_DA | CRMD_PG | CRMD_IE
    li.w $t1, CRMD_DA | CRMD_PG | CRMD_IE
    xori $t0, $t0, CRMD_DA | CRMD_IE
    csrxchg $t0, $t1, CSR_CRMD
    ibar 0
    dbar 0

    jr $s0

.global laboot_ap_entry
.type laboot_ap_entry, @function
laboot_ap_entry:
    csrrd $a0, CSR_CPUID

    load_abs $t0, ap_startup_info

    ld.d $t1, $t0, 0
    csrwr $t1, CSR_PWCTL0
    ld.d $t1, $t0, 8
    csrwr $t1, CSR_PWCTL1
    ld.d $t1, $t0, 16
    csrwr $t1, CSR_STLBPGSIZE

    ld.d $t1, $t0, 24
    csrwr $t1, CSR_PGDL
    ld.d $t1, $t0, 32
    csrwr $t1, CSR_PGDH
    invtlb 0, $zero, $zero

    ld.d $t1, $t0, 40
    csrwr $t1, CSR_DMWIN0
    ld.d $t1, $t0, 48
    csrwr $t1, CSR_DMWIN1
    ld.d $t1, $t0, 56
    csrwr $t1, CSR_DMWIN2
    ld.d $t1, $t0, 64
    csrwr $t1, CSR_DMWIN3
    ld.d $t1, $t0, 72
    csrwr $t1, CSR_TLBRENTRY

    ld.d $sp, $t0, 80
    ld.d $t2, $t0, 88

    li.w $t3, CRMD_DA | CRMD_PG | CRMD_IE
    li.w $t4, CRMD_DA | CRMD_PG | CRMD_IE
    xori $t3, $t3, CRMD_DA | CRMD_IE
    csrxchg $t3, $t4, CSR_CRMD
    ibar 0
    dbar 0

    jirl $zero, $t2, 0

.align 12
.global boot_tlb_refill
.type boot_tlb_refill, @function
boot_tlb_refill:
    csrwr $t0, CSR_TLBRSAVE
    csrrd $t0, CSR_PGD
    lddir $t0, $t0, 3
    lddir $t0, $t0, 2
    lddir $t0, $t0, 1
    ldpte $t0, 0
    ldpte $t0, 1
    tlbfill
    csrrd $t0, CSR_TLBRSAVE
    ertn

.section .text, "ax", @progbits
.type high_entry, @function
high_entry:
    la.pcrel $t0, __bss_start
    la.pcrel $t1, __bss_end
1:
    beq $t0, $t1, 2f
    st.d $zero, $t0, 0
    addi.d $t0, $t0, 8
    b 1b
2:
    load_abs $t0, boot_info
    phys_to_hhdm $t0

    ld.d $a0, $t0, 0
    ld.d $a1, $t0, 16
    move $a2, $t0

    la.pcrel $t1, laboot_main
    jirl $ra, $t1, 0

1:
    idle 0
    b 1b

.section .boot.bss, "aw", @nobits
.align 12
.global boot_pt_begin
boot_pt_begin:
.global boot_root_pt
boot_root_pt:
    .skip 4096
boot_low_l2_pt:
    .skip 4096
boot_low_l3_pt:
    .skip 4096
.global boot_high_l2_pt
boot_high_l2_pt:
    .skip 4096
.global boot_hhdm_l3_pt
boot_hhdm_l3_pt:
    .skip 4096 * HHDM_L2_TABLE_COUNT
boot_kernel_l3_pt:
    .skip 4096
boot_low_pt_pages:
    .skip 4096 * BOOT_L3_COUNT
.global boot_hhdm_pt_pages
boot_hhdm_pt_pages:
    .skip 4096 * BOOT_L3_COUNT
boot_kernel_pt_pages:
    .skip 4096 * BOOT_L3_COUNT
.global boot_pt_end
boot_pt_end:
boot_stack:
    .skip STACK_SIZE
.global boot_stack_top
boot_stack_top:

.section .boot.data, "aw", @progbits
.align 3
.global boot_info
boot_info:
    .quad 0 /* bsp_phys_id */
    .quad 0 /* dtb_phys */
    .quad 0 /* dtb_virt */
    .quad 0 /* hhdm_base */
    .quad 0 /* kernel_phys_base */
    .quad 0 /* kernel_virt_base */
    .quad 0 /* kernel_phys_end */
    .quad 0 /* kernel_virt_end */
    .quad 0 /* root_page_table_phys */
    .quad 0 /* root_page_table_virt */
    .quad 0 /* cmdline_phys */
    .quad 0 /* system_table_phys */
    .quad 0 /* cmdline_virt */
    .quad 0 /* system_table_virt */

.section .boot.data, "aw", @progbits
.align 3
.global ap_startup_info
ap_startup_info:
    .quad 0 /* pwctl0 */
    .quad 0 /* pwctl1 */
    .quad 0 /* stlbpgsize */
    .quad 0 /* pgdl */
    .quad 0 /* pgdh */
    .quad 0 /* dmw0 */
    .quad 0 /* dmw1 */
    .quad 0 /* dmw2 */
    .quad 0 /* dmw3 */
    .quad 0 /* tlbrentry */
    .quad 0 /* stack_top */
    .quad 0 /* entry */
