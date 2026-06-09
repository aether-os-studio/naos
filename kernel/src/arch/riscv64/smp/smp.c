#include <arch/arch.h>
#include <arch/riscv64/time/time.h>
#include <boot/boot.h>
#include <arch/riscv64/cpu_local.h>
#include <irq/irq_manager.h>
#include <limine.h>
#include <mm/mm.h>
#include <task/task.h>
#include <task/watchdog.h>

void ap_entry(uint64_t hartid);
extern void setup_trap_vector();
extern bool task_initialized;

uint64_t cpu_count = 0;
uint64_t cpuid_to_hartid[MAX_CPU_NUM];
static uint64_t sched_ipi_irq = ARCH_MAX_IRQ_NUM;

spinlock_t ap_startup_lock = SPIN_INIT;

static inline uint64_t riscv64_sbi_ecall(uint64_t eid, uint64_t fid,
                                         uint64_t arg0, uint64_t arg1,
                                         uint64_t arg2, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5) {
    register uint64_t a0 asm("a0") = arg0;
    register uint64_t a1 asm("a1") = arg1;
    register uint64_t a2 asm("a2") = arg2;
    register uint64_t a3 asm("a3") = arg3;
    register uint64_t a4 asm("a4") = arg4;
    register uint64_t a5 asm("a5") = arg5;
    register uint64_t a6 asm("a6") = fid;
    register uint64_t a7 asm("a7") = eid;

    asm volatile("ecall"
                 : "+r"(a0), "+r"(a1)
                 : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
                 : "memory");
    return a0;
}

static int64_t riscv64_sbi_send_ipi(uint64_t hart_mask,
                                    uint64_t hart_mask_base) {
    return (int64_t)riscv64_sbi_ecall(0x735049ULL, 0, hart_mask, hart_mask_base,
                                      0, 0, 0, 0);
}

static int64_t riscv64_sched_ipi_unmask(uint64_t irq, uint64_t flags) {
    (void)irq;
    (void)flags;
    uint64_t ssie = 1UL << 1;
    asm volatile("csrs sie, %0" : : "r"(ssie) : "memory");
    return 0;
}

static int64_t riscv64_sched_ipi_mask(uint64_t irq, uint64_t flags) {
    (void)irq;
    (void)flags;
    uint64_t ssie = 1UL << 1;
    asm volatile("csrc sie, %0" : : "r"(ssie) : "memory");
    return 0;
}

static int64_t riscv64_sched_ipi_install(uint64_t irq, uint64_t arg,
                                         uint64_t flags) {
    (void)irq;
    (void)arg;
    (void)flags;
    return 0;
}

static int64_t riscv64_sched_ipi_ack(uint64_t irq) {
    (void)irq;
    uint64_t ssip = 1UL << 1;
    asm volatile("csrc sip, %0" : : "r"(ssip) : "memory");
    return 0;
}

static void riscv64_sched_ipi_handler(uint64_t irq_num, void *data,
                                      struct pt_regs *regs) {
    (void)irq_num;
    (void)data;
    (void)regs;
}

static void riscv64_sched_ipi_send(uint32_t cpu_id, uint64_t irq_num) {
    (void)irq_num;
    if (cpu_id >= cpu_count)
        return;

    uint64_t hartid = cpuid_to_hartid[cpu_id];
    if (hartid >= 64)
        return;

    riscv64_sbi_send_ipi(1UL << hartid, 0);
}

static irq_controller_t riscv64_sched_ipi_controller = {
    .unmask = riscv64_sched_ipi_unmask,
    .mask = riscv64_sched_ipi_mask,
    .install = riscv64_sched_ipi_install,
    .ack = riscv64_sched_ipi_ack,
};

uint64_t current_hartid() {
    riscv64_cpu_local_t *local = riscv64_get_cpu_local();
    return local ? local->hartid : boot_get_bsp_hartid();
}

uint64_t get_cpuid_by_hartid(uint64_t hartid) {
    for (uint64_t i = 0; i < cpu_count; i++) {
        if (cpuid_to_hartid[i] == hartid)
            return i;
    }
    return 0;
}

uint64_t riscv64_sched_ipi_irq(void) { return sched_ipi_irq; }

void limine_ap_stub(struct limine_mp_info *cpu);

void smp_init() {
#ifdef CONFIG_BOOT_SBI
    boot_smp_init((uintptr_t)ap_entry);
#endif
#ifdef CONFIG_BOOT_LIMINE
    boot_smp_init((uintptr_t)limine_ap_stub);
#endif

    sched_ipi_irq = irq_allocate_irqnum();
    irq_regist_ipi(sched_ipi_irq, riscv64_sched_ipi_handler, 0, NULL,
                   &riscv64_sched_ipi_controller, "SBI SCHED IPI", 0,
                   riscv64_sched_ipi_send);
    irq_set_sched_ipi(sched_ipi_irq);
}

void ap_entry(uint64_t hartid) {
    arch_disable_interrupt();

    riscv64_set_page_table_root((uint64_t)virt_to_phys(get_kernel_page_dir()));

    uint32_t cpu_id = (uint32_t)get_cpuid_by_hartid(hartid);
    riscv64_cpu_local_init(cpu_id, hartid);
    setup_trap_vector();

    raw_spin_unlock(&ap_startup_lock);

    while (!__atomic_load_n(&task_initialized, __ATOMIC_ACQUIRE)) {
        asm volatile("nop" ::: "memory");
    }

    arch_set_current(idle_tasks[cpu_id]);
    task_mark_on_cpu(idle_tasks[cpu_id], true);
    task_mm_mark_cpu_active(idle_tasks[cpu_id]->mm, cpu_id);
    sched_watchdog_note_current(cpu_id, idle_tasks[cpu_id], nano_time());

    while (!__atomic_load_n(&global_timer.initialized, __ATOMIC_ACQUIRE)) {
        asm volatile("nop" ::: "memory");
    }

    timer_init_percpu();

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}

void limine_ap_stub(struct limine_mp_info *cpu) { ap_entry(cpu->hartid); }
