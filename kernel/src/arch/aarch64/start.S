.section .text

.global _start
_start:
    mrs x0, CurrentEL
    lsr x0, x0, #2
    and x0, x0, #3
    
    cmp x0, #2
    b.eq drop_from_el2
    cmp x0, #1
    b.eq already_el1
    
unexpected_el:
    b .

drop_from_el2:
    // 配置HCR_EL2
    mov x0, #(1 << 31)      // RW=1: EL1是AArch64
    msr HCR_EL2, x0
    
    // 配置CNTHCTL_EL2
    mov x0, #3              // EL1PCTEN | EL1PCEN
    msr CNTHCTL_EL2, x0
    
    // 配置CNTVOFF_EL2
    msr CNTVOFF_EL2, xzr
    
    // 配置SPSR_EL2
    mov x0, #0x3c5          // EL1h + 屏蔽中断
    msr SPSR_EL2, x0
    
    // 返回到el1
    adr x0, already_el1
    msr ELR_EL2, x0
    
    eret

already_el1:
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
    mrs x0, CurrentEL
    lsr x0, x0, #2
    and x0, x0, #3
    
    cmp x0, #2
    b.eq drop_from_el2_ap
    cmp x0, #1
    b.eq already_el1_ap
    
unexpected_el_ap:
    b .

drop_from_el2_ap:
    // 配置HCR_EL2
    mov x0, #(1 << 31)      // RW=1: EL1是AArch64
    msr HCR_EL2, x0
    
    // 配置CNTHCTL_EL2
    mov x0, #3              // EL1PCTEN | EL1PCEN
    msr CNTHCTL_EL2, x0
    
    // 配置CNTVOFF_EL2
    msr CNTVOFF_EL2, xzr
    
    // 配置SPSR_EL2
    mov x0, #0x3c5          // EL1h + 屏蔽中断
    msr SPSR_EL2, x0
    
    // 返回到el1
    adr x0, already_el1_ap
    msr ELR_EL2, x0
    
    eret

already_el1_ap:
    mov     x2, sp

    mov     x1, #1
    msr     spsel, x1
    mov     sp, x2

    mrs     x1, cpacr_el1
    orr     x1, x1, #(0x3 << 20)
    msr     cpacr_el1, x1

    b ap_kmain
