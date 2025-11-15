#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <boot/boot.h>
#include <drivers/fdt/fdt.h>

extern void gic_init();

void arch_early_init() {
    setup_vectors();

    struct fdt_header *header;
    header = (struct fdt_header *)boot_get_dtb();
    if (!header) {
        goto next;
    }

    /* 检查魔数 */
    if (fdt32_to_cpu(header->magic) != FDT_MAGIC) {
        goto next;
    }

    /* 获取DTB总大小 */
    g_fdt_ctx.dtb_base = (void *)header;
    if (!g_fdt_ctx.dtb_base) {
        goto next;
    }

    /* 设置各个部分的指针 */
    g_fdt_ctx.header = (struct fdt_header *)g_fdt_ctx.dtb_base;
    g_fdt_ctx.dt_struct =
        (uint8_t *)g_fdt_ctx.dtb_base + fdt32_to_cpu(header->off_dt_struct);
    g_fdt_ctx.dt_strings =
        (char *)g_fdt_ctx.dtb_base + fdt32_to_cpu(header->off_dt_strings);
    g_fdt_ctx.rsv_map =
        (struct fdt_reserve_entry *)((uint8_t *)g_fdt_ctx.dtb_base +
                                     fdt32_to_cpu(header->off_mem_rsvmap));

next:
    init_serial();
    smp_init();
}

extern task_t *idle_tasks[MAX_CPU_NUM];

extern void syscall_handlers_init();

void arch_init() {
    arch_set_current(idle_tasks[current_cpu_id]);

    syscall_handlers_init();

    gic_init();

    irq_init();

    arch_enable_interrupt();
}

void arch_init_after_thread() { pci_brcmstb_init(); }

void arch_input_dev_init() {}
