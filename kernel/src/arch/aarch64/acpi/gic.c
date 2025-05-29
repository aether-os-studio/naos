#include <arch/aarch64/acpi/acpi.h>
#include <arch/aarch64/acpi/gic.h>
#include <interrupt/irq_manager.h>
#include <mm/mm.h>

uint64_t gicd_base_virt = 0;
uint64_t gicd_base_address = 0;
uint64_t gicr_base_virt = 0;
uint64_t gicr_base_address = 0;

void madt_setup(MADT *madt)
{
    if (!madt)
        return;

    uint64_t current = 0;
    for (;;)
    {
        if (current + ((uint32_t)sizeof(MADT) - 1) >= madt->h.length)
        {
            break;
        }
        MadtHeader *header = (MadtHeader *)((uint64_t)(&madt->entries) + current);
        if (header->entry_type == ACPI_MADT_TYPE_GICD)
        {
            GicdEntry *gicd = (GicdEntry *)((uint64_t)(&madt->entries) + current);
            gicd_base_address = gicd->base_address;
            break;
        }
        current += (uint64_t)header->length;
    }

    current = 0;
    for (;;)
    {
        if (current + ((uint32_t)sizeof(MADT) - 1) >= madt->h.length)
        {
            break;
        }
        MadtHeader *header = (MadtHeader *)((uint64_t)(&madt->entries) + current);
        if (header->entry_type == ACPI_MADT_TYPE_GICR)
        {

            GicrEntry *gicr = (GicrEntry *)((uint64_t)(&madt->entries) + current);
            gicr_base_address = gicr->discovery_range_base_address;
            break;
        }
        current += (uint64_t)header->length;
    }

    // current = 0;
    // for (;;)
    // {
    //     if (current + ((uint32_t)sizeof(MADT) - 1) >= madt->h.Length)
    //     {
    //         break;
    //     }
    //     MadtHeader *header = (MadtHeader *)((uint64_t)(&madt->entries) + current);
    //     if (header->entry_type == ACPI_MADT_TYPE_GICC)
    //     {

    //         GiccEntry *gicc = (GiccEntry *)((uint64_t)(&madt->entries) + current);
    //         gicr_base_address = gicc->gicr_base_address;
    //         break;
    //     }
    //     current += (uint64_t)header->length;
    // }

    if (gicd_base_address)
    {
        gicd_base_virt = phys_to_virt(gicd_base_address);
        map_page_range(get_current_page_dir(false), gicd_base_virt, gicd_base_address, 0x10000, PT_FLAG_R | PT_FLAG_W);
    }

    if (gicr_base_address)
    {
        gicr_base_virt = phys_to_virt(gicr_base_address);
        map_page_range(get_current_page_dir(false), gicr_base_virt, gicr_base_address, GICR_STRIDE * cpu_count, PT_FLAG_R | PT_FLAG_W);
    }
}

// 内存屏障宏
#define dsb(op) __asm__ __volatile__("dsb " #op : : : "memory")
#define isb() __asm__ __volatile__("isb" : : : "memory")

// 中断控制函数
void gic_enable_irq(uint32_t irq);
void gic_disable_irq(uint32_t irq);
void gic_send_eoi(uint32_t irq);

// 初始化GICv3 Distributor
static void gicd_init(void)
{
    // 1. 禁用GICD
    *(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) = 0x0;

    // 2. 配置SPI中断路由
    for (int intr = SPI_INTR_BASE; intr < 1020; intr += 4)
    {
        volatile uint32_t *route_reg = (uint32_t *)(gicd_base_virt + 0x6100 + (intr / 4) * 4);
        *route_reg = 0xFFFFFFFF; // 路由到所有CPU[10](@ref)
    }

    // 3. 设置所有SPI中断优先级
    for (int i = 0; i < 256; i++)
    {
        volatile uint32_t *prio_reg = (uint32_t *)(gicd_base_virt + GICD_IPRIORITYR + i * 4);
        *prio_reg = 0xA0A0A0A0; // 默认优先级0xA0[8](@ref)
    }

    // 4. 启用GICD
    *(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) = GICD_CTLR_EN_GRP0 | GICD_CTLR_EN_GRP1_ALL | GICD_CTLR_DS; // 使能Group0/1
}

// 初始化单个CPU的Redistributor
static void gicr_init(uint32_t cpu_id)
{
    // 1. 唤醒Redistributor
    volatile uint32_t *waker = (uint32_t *)(gicr_base_virt + cpu_id * GICR_STRIDE + GICR_WAKER);
    *waker &= ~(1 << 1); // 清除ProcessorSleep位
    while (*waker & (1 << 2))
        asm volatile("nop"); // 等待ChildrenAsleep清零

    // 2. 配置PPI/SGI中断组
    *(volatile uint32_t *)(gicr_base_virt + cpu_id * GICR_STRIDE + GICR_IGROUPR0) = 0xFFFFFFFF; // Group1使能

    // 3. 启用私有中断
    *(volatile uint32_t *)(gicr_base_virt + cpu_id * GICR_STRIDE + GICR_ISENABLER0) = 0xFFFFFFFF; // 全部使能[3](@ref)
}

// 初始化CPU接口
static void cpu_interface_init(void)
{
    // 1. 设置优先级掩码
    asm volatile("msr ICC_PMR_EL1, %0" : : "r"(0xF0)); // 优先级阈值0xF0

    // 2. 启用CPU接口
    asm volatile(
        "mov x0, #1\n\t" // EnableGrp1
        "msr ICC_IGRPEN1_EL1, x0"
        : : : "x0");
}

/* 初始化核心函数 */
void gic_v3_init(void)
{
    gicd_init();

    gicr_init(current_cpu_id);

    cpu_interface_init();
}

void gic_v3_init_percpu()
{
    gicr_init(current_cpu_id);

    cpu_interface_init();
}

// 定时器寄存器定义
#define CNTP_CTL_EL0 "S3_3_C14_C2_1"  // 物理定时器控制寄存器
#define CNTP_TVAL_EL0 "S3_3_C14_C2_0" // 物理定时器计数值寄存器

// 定时器初始化函数
void timer_init_percpu()
{
    // 1. 获取定时器频率并计算1ms间隔
    uint64_t cntfrq;
    asm volatile("mrs %0, CNTFRQ_EL0" : "=r"(cntfrq));

    uint64_t ticks = cntfrq / 10; // 100ms

    // 2. 配置物理定时器（CNTP）
    asm volatile("msr S3_3_C14_C2_0, %0" : : "r"(ticks));

    // 启用定时器（bit0:使能）
    asm volatile("msr S3_3_C14_C2_1, %0" : : "r"(0x1));

    // // 3. 配置PPI中断（TIMER_IRQ=30）
    uint64_t gicr_addr = gicr_base_virt + current_cpu_id * GICR_STRIDE;

    // 3.2 设置中断优先级（GICR_IPRIORITYR）
    uint8_t *gicr_ipriority =
        (uint8_t *)(gicr_addr + GICR_IPRIORITYR);
    gicr_ipriority[TIMER_IRQ - 16] = 0x80; // 中等优先级（0x8）

    // 3.3 配置中断路由（GICD_ITARGETSR）
    uint32_t *gicd_itargetsr =
        (uint32_t *)(gicd_base_virt + GICD_ITARGETSR + ((TIMER_IRQ / 32) * 4));
    *gicd_itargetsr = (1 << current_cpu_id); // 路由到当前CPU
}

/* 中断控制函数 */
// 启用中断（支持SPI/PPI/SGI）
void gic_enable_irq(uint32_t irq)
{
    if (irq < 32)
    {
        uint64_t reg = gicr_base_virt + current_cpu_id * GICR_STRIDE + GICR_ISENABLER0 + (irq / 32) * 4;
        *(uint32_t *)reg = (1 << (irq % 32));
    }
    else if (irq < ARCH_MAX_IRQ_NUM)
    { // SPI（网页6）
        uint64_t reg = gicd_base_virt + GICD_ISENABLER + (irq / 32) * 4;
        *(uint32_t *)reg = (1 << (irq % 32));
    }
}

// 禁用中断
void gic_disable_irq(uint32_t irq)
{
    if (irq < 32)
    {
        uint64_t reg = gicr_base_virt + current_cpu_id * GICR_STRIDE + GICR_ICENABLER0 + (irq / 32) * 4;
        *(uint32_t *)reg = (1 << (irq % 32));
    }
    else if (irq < ARCH_MAX_IRQ_NUM)
    {
        uint64_t reg = gicd_base_virt + GICD_ICENABLER + (irq / 32) * 4;
        *(uint32_t *)reg = (1 << (irq % 32));
    }
}

void gic_send_eoi(uint32_t irq)
{
    // 发送EOI到CPU接口
    asm volatile("msr ICC_EOIR1_EL1, %0" : : "r"(irq));
    isb();
}

uint64_t gic_v3_get_current_irq()
{
    uint64_t irq_num = 0;
    asm volatile("mrs %0, ICC_IAR1_EL1" : "=r"(irq_num));
    return irq_num;
}

err_t gic_unmask(uint64_t irq)
{
    gic_enable_irq(irq);
    return 0;
}

err_t gic_mask(uint64_t irq)
{
    gic_disable_irq(irq);
    return 0;
}

err_t gic_ack(uint64_t irq)
{
    gic_send_eoi(irq);
    return 0;
}

irq_controller_t gic_controller =
    {
        .unmask = gic_unmask,
        .mask = gic_mask,
        .ack = gic_ack,
};
