#pragma once

#include <libs/klibc.h>
#include <arch/aarch64/smp/smp.h>

extern uint64_t gicd_base_virt;
extern uint64_t gicr_base_virt;

#define TIMER_IRQ 30

// GIC寄存器基地址（需根据具体SoC手册调整）
#define GICR_STRIDE 0x20000 // Per-CPU Redistributor间隔

#define GICR_SGI_OFFSET 0x10000

/* Distributor registers, as offsets from the distributor base address */
#define GICD_CTLR 0x0000
#define GICD_TYPER 0x0004
#define GICD_IIDR 0x0008
#define GICD_STATUSR 0x0010
#define GICD_SETSPI_NSR 0x0040
#define GICD_CLRSPI_NSR 0x0048
#define GICD_SETSPI_SR 0x0050
#define GICD_CLRSPI_SR 0x0058
#define GICD_SEIR 0x0068
#define GICD_IGROUPR 0x0080
#define GICD_ISENABLER 0x0100
#define GICD_ICENABLER 0x0180
#define GICD_ISPENDR 0x0200
#define GICD_ICPENDR 0x0280
#define GICD_ISACTIVER 0x0300
#define GICD_ICACTIVER 0x0380
#define GICD_IPRIORITYR 0x0400
#define GICD_ITARGETSR 0x0800
#define GICD_ICFGR 0x0C00
#define GICD_IGRPMODR 0x0D00
#define GICD_NSACR 0x0E00
#define GICD_SGIR 0x0F00
#define GICD_CPENDSGIR 0x0F10
#define GICD_SPENDSGIR 0x0F20
#define GICD_INMIR 0x0F80
#define GICD_INMIRnE 0x3B00
#define GICD_IROUTER 0x6000
#define GICD_IDREGS 0xFFD0

/* GICD_CTLR fields  */
#define GICD_CTLR_EN_GRP0 (1U << 0)
#define GICD_CTLR_EN_GRP1NS (1U << 1) /* GICv3 5.3.20 */
#define GICD_CTLR_EN_GRP1S (1U << 2)
#define GICD_CTLR_EN_GRP1_ALL (GICD_CTLR_EN_GRP1NS | GICD_CTLR_EN_GRP1S)
/* Bit 4 is ARE if the system doesn't support TrustZone, ARE_S otherwise */
#define GICD_CTLR_ARE (1U << 4)
#define GICD_CTLR_ARE_S (1U << 4)
#define GICD_CTLR_ARE_NS (1U << 5)
#define GICD_CTLR_DS (1U << 6)
#define GICD_CTLR_E1NWF (1U << 7)
#define GICD_CTLR_RWP (1U << 31)

/* GICD_CTLR fields  */
#define GICD_CTLR_EN_GRP0 (1U << 0)
#define GICD_CTLR_EN_GRP1NS (1U << 1) /* GICv3 5.3.20 */
#define GICD_CTLR_EN_GRP1S (1U << 2)
#define GICD_CTLR_EN_GRP1_ALL (GICD_CTLR_EN_GRP1NS | GICD_CTLR_EN_GRP1S)
/* Bit 4 is ARE if the system doesn't support TrustZone, ARE_S otherwise */
#define GICD_CTLR_ARE (1U << 4)
#define GICD_CTLR_ARE_S (1U << 4)
#define GICD_CTLR_ARE_NS (1U << 5)
#define GICD_CTLR_DS (1U << 6)
#define GICD_CTLR_E1NWF (1U << 7)
#define GICD_CTLR_RWP (1U << 31)

/*
 * Redistributor registers, offsets from RD_base
 */
#define GICR_CTLR 0x0000
#define GICR_IIDR 0x0004
#define GICR_TYPER 0x0008
#define GICR_STATUSR 0x0010
#define GICR_WAKER 0x0014
#define GICR_SETLPIR 0x0040
#define GICR_CLRLPIR 0x0048
#define GICR_PROPBASER 0x0070
#define GICR_PENDBASER 0x0078
#define GICR_INVLPIR 0x00A0
#define GICR_INVALLR 0x00B0
#define GICR_SYNCR 0x00C0
#define GICR_IDREGS 0xFFD0

/* SGI and PPI Redistributor registers, offsets from RD_base */
#define GICR_IGROUPR0 (GICR_SGI_OFFSET + 0x0080)
#define GICR_ISENABLER0 (GICR_SGI_OFFSET + 0x0100)
#define GICR_ICENABLER0 (GICR_SGI_OFFSET + 0x0180)
#define GICR_ISPENDR0 (GICR_SGI_OFFSET + 0x0200)
#define GICR_ICPENDR0 (GICR_SGI_OFFSET + 0x0280)
#define GICR_ISACTIVER0 (GICR_SGI_OFFSET + 0x0300)
#define GICR_ICACTIVER0 (GICR_SGI_OFFSET + 0x0380)
#define GICR_IPRIORITYR (GICR_SGI_OFFSET + 0x0400)
#define GICR_ICFGR0 (GICR_SGI_OFFSET + 0x0C00)
#define GICR_ICFGR1 (GICR_SGI_OFFSET + 0x0C04)
#define GICR_IGRPMODR0 (GICR_SGI_OFFSET + 0x0D00)
#define GICR_NSACR (GICR_SGI_OFFSET + 0x0E00)
#define GICR_INMIR0 (GICR_SGI_OFFSET + 0x0F80)

// 中断类型宏
#define SPI_INTR_BASE 32 // SPI中断起始ID[3](@ref)
#define PPI_INTR_BASE 16 // PPI中断起始ID
#define SGI_INTR_BASE 0  // SGI中断起始ID

struct irq_controller;
extern struct irq_controller gic_controller;

void gic_v3_init();
void gic_v3_init_percpu();
void timer_init_percpu();
uint64_t gic_v3_get_current_irq();
