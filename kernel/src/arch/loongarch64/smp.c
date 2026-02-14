#include <arch/arch.h>
#include <boot/boot.h>

uint64_t cpu_count = 0;
spinlock_t ap_startup_lock = SPIN_INIT;

extern void _ap_start(void);

uint64_t cpuid_to_physid[MAX_CPU_NUM];

void smp_init(void) { boot_smp_init((uintptr_t)_ap_start); }

extern void trap_entry();

void ap_kmain() {
    // 设置异常入口地址（必须 4KB 对齐）
    uint64_t eentry = (uint64_t)trap_entry;
    csr_write(LOONGARCH_CSR_EENTRY, eentry);

    // 配置异常控制
    csr_write(LOONGARCH_CSR_ECFG, 0);  // 初始禁用所有中断
    csr_write(LOONGARCH_CSR_ESTAT, 0); // 清除中断状态

    spin_unlock(&ap_startup_lock);

    printk("AP %d started\n", csr_read(0x20));

    // 配置时钟中断
    csr_write(0x41, 1000000 | 0b11);

    // 使能全局中断
    uint64_t crmd = csr_read(LOONGARCH_CSR_CRMD);
    crmd |= CSR_CRMD_IE;
    csr_write(LOONGARCH_CSR_CRMD, crmd);

    while (1) {
        arch_pause();
    }
}
