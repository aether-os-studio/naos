.section .text

.global _start
_start:
    mov     x1, sp

    mov     x0, #1
    msr     spsel, x0
    mov     sp, x1

    mrs     x0, cpacr_el1
    orr     x0, x0, #(0x3 << 20)
    msr     cpacr_el1, x0

    b kmain

.global ap_entry
ap_entry:
    mov     x2, sp

    mov     x1, #1
    msr     spsel, x1
    mov     sp, x2

    mrs     x0, cpacr_el1
    orr     x0, x0, #(0x3 << 20)
    msr     cpacr_el1, x0

    b ap_kmain
