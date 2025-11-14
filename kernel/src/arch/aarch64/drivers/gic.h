#pragma once

#include <libs/klibc.h>
#include <arch/aarch64/smp/smp.h>

// GIC版本枚举
typedef enum {
    GIC_VERSION_UNKNOWN = 0,
    GIC_VERSION_V2 = 2,
    GIC_VERSION_V3 = 3,
    GIC_VERSION_V4 = 4,
} gic_version_t;

extern uint64_t gicd_base_virt;
extern uint64_t gicc_base_virt; // GICv2 only
extern uint64_t gicr_base_virt; // GICv3 only
extern gic_version_t gic_version;

// GIC寄存器基地址
#define GICR_STRIDE 0x20000
#define GICR_SGI_OFFSET 0x10000

/* Distributor registers (GICv2 & GICv3 共用) */
#define GICD_CTLR 0x0000
#define GICD_TYPER 0x0004
#define GICD_IIDR 0x0008
#define GICD_STATUSR 0x0010
#define GICD_IGROUPR 0x0080
#define GICD_ISENABLER 0x0100
#define GICD_ICENABLER 0x0180
#define GICD_ISPENDR 0x0200
#define GICD_ICPENDR 0x0280
#define GICD_ISACTIVER 0x0300
#define GICD_ICACTIVER 0x0380
#define GICD_IPRIORITYR 0x0400
#define GICD_ITARGETSR 0x0800 // GICv2 only
#define GICD_ICFGR 0x0C00
#define GICD_IGRPMODR 0x0D00
#define GICD_SGIR 0x0F00    // GICv2 only
#define GICD_IROUTER 0x6000 // GICv3 only

/* GICD_CTLR fields */
#define GICD_CTLR_EN_GRP0 (1U << 0)
#define GICD_CTLR_EN_GRP1NS (1U << 1)
#define GICD_CTLR_EN_GRP1S (1U << 2)
#define GICD_CTLR_EN_GRP1_ALL (GICD_CTLR_EN_GRP1NS | GICD_CTLR_EN_GRP1S)
#define GICD_CTLR_ARE (1U << 4)
#define GICD_CTLR_ARE_S (1U << 4)
#define GICD_CTLR_ARE_NS (1U << 5)
#define GICD_CTLR_DS (1U << 6)
#define GICD_CTLR_RWP (1U << 31)

/* Redistributor registers (GICv3) */
#define GICR_CTLR 0x0000
#define GICR_TYPER 0x0008
#define GICR_WAKER 0x0014
#define GICR_IGROUPR0 (GICR_SGI_OFFSET + 0x0080)
#define GICR_ISENABLER0 (GICR_SGI_OFFSET + 0x0100)
#define GICR_ICENABLER0 (GICR_SGI_OFFSET + 0x0180)
#define GICR_ISPENDR0 (GICR_SGI_OFFSET + 0x0200)
#define GICR_ICPENDR0 (GICR_SGI_OFFSET + 0x0280)
#define GICR_IPRIORITYR (GICR_SGI_OFFSET + 0x0400)
#define GICR_ICFGR0 (GICR_SGI_OFFSET + 0x0C00)
#define GICR_ICFGR1 (GICR_SGI_OFFSET + 0x0C04)

/* CPU Interface registers (GICv2) */
#define GICC_CTLR 0x000
#define GICC_PMR 0x004
#define GICC_BPR 0x008
#define GICC_IAR 0x00C
#define GICC_EOIR 0x010
#define GICC_RPR 0x014
#define GICC_HPPIR 0x018
#define GICC_DIR 0x1000

/* 中断类型 */
#define SGI_INTR_BASE 0
#define PPI_INTR_BASE 16
#define SPI_INTR_BASE 32

struct irq_controller;
extern struct irq_controller gic_controller;

/* 公共API */
void gic_init(void);
void gic_init_percpu(void);
void gic_enable_irq(uint32_t irq);
void gic_disable_irq(uint32_t irq);
void gic_send_eoi(uint32_t irq);
uint64_t gic_get_current_irq(void);

/* 版本检测 */
gic_version_t gic_detect_version(void);
