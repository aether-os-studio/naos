#include <arch/arch.h>
#include <drivers/kernel_logger.h>

extern void trap_entry();
extern void tlb_refill_entry();

static trap_handler_t trap_handlers[64];

extern void do_irq(struct pt_regs *regs, uint64_t irq_num);

void handle_interrupt(struct pt_regs *regs) {
    // 获取中断状态
    uint64_t estat = regs->csr_estat;
    uint32_t int_vec = (estat >> 0) & 0x1fff; // IS[12:0]

    do_irq(regs, int_vec);
}

void handle_exception_page_fault(struct pt_regs *regs) {
    uint64_t badv = regs->csr_badvaddr;
    uint64_t era = regs->csr_era;
    uint32_t ecode = (regs->csr_estat >> 16) & 0x3f;

    const char *type;
    switch (ecode) {
    case EXCCODE_PIL:
        type = "Load";
        break;
    case EXCCODE_PIS:
        type = "Store";
        break;
    case EXCCODE_PIF:
        type = "Fetch";
        break;
    default:
        type = "Unknown";
        break;
    }

    printk("Page Fault (%s) at PC: 0x%lx, Bad Address: 0x%lx\n", type, era,
           badv);
}

// 系统调用处理
void handle_syscall(struct pt_regs *regs) {
    // 跳过 syscall 指令（4字节）
    regs->csr_era += 4;
}

// 断点异常
void handle_breakpoint(struct pt_regs *regs) {
    printk("Breakpoint at PC: 0x%lx\n", regs->csr_era);
}

// 非法指令
void handle_reserved_instruction(struct pt_regs *regs) {
    printk("Reserved Instruction at PC: 0x%lx\n", regs->csr_era);
}

// 地址错误
void handle_address_error(struct pt_regs *regs) {
    printk("Address Error at PC: 0x%lx, Bad Address: 0x%lx\n", regs->csr_era,
           regs->csr_badvaddr);
}

// 默认异常处理
void handle_default(struct pt_regs *regs) {
    uint32_t ecode = (regs->csr_estat >> 16) & 0x3f;
    printk("Unhandled trap: Code=0x%x, PC=0x%lx\n", ecode, regs->csr_era);

    // 打印寄存器状态
    printk("Register Dump:\n");
    printk("  ra=0x%016lx  tp=0x%016lx  sp=0x%016lx\n", regs->ra, regs->tp,
           regs->usp);
    printk("  a0=0x%016lx  a1=0x%016lx  a2=0x%016lx\n", regs->a0, regs->a1,
           regs->a2);

    // TODO: 致命错误处理
    while (1)
        arch_pause(); // 停机
}

void trap_handle_c(struct pt_regs *regs) {
    // 从 ESTAT 获取异常码
    uint32_t ecode = (regs->csr_estat >> 16) & 0x3f;

    // 调用对应的异常处理函数
    trap_handler_t handler = trap_handlers[ecode];
    if (handler) {
        handler(regs);
    } else {
        handle_default(regs);
    }
}

void trap_init() {
    // 初始化异常处理函数表
    memset(trap_handlers, 0, sizeof(trap_handlers));

    trap_handlers[EXCCODE_INT] = handle_interrupt;
    trap_handlers[EXCCODE_PIL] = handle_exception_page_fault;
    trap_handlers[EXCCODE_PIS] = handle_exception_page_fault;
    trap_handlers[EXCCODE_PIF] = handle_exception_page_fault;
    trap_handlers[EXCCODE_PME] = handle_exception_page_fault;
    trap_handlers[EXCCODE_ADEF] = handle_address_error;
    trap_handlers[EXCCODE_ADEM] = handle_address_error;
    trap_handlers[EXCCODE_SYS] = handle_syscall;
    trap_handlers[EXCCODE_BRK] = handle_breakpoint;
    trap_handlers[EXCCODE_INE] = handle_reserved_instruction;

    // 设置异常入口地址（必须 4KB 对齐）
    uint64_t eentry = (uint64_t)trap_entry;
    csr_write(LOONGARCH_CSR_EENTRY, eentry);
    printk("  EENTRY = 0x%lx\n", eentry);

    // 设置 TLB 重填异常入口
    uint64_t tlbrentry = (uint64_t)tlb_refill_entry;
    csr_write(LOONGARCH_CSR_TLBRENTRY, tlbrentry);
    printk("  TLBRENTRY = 0x%lx\n", tlbrentry);

    // 配置异常控制
    csr_write(LOONGARCH_CSR_ECFG, 0);  // 初始禁用所有中断
    csr_write(LOONGARCH_CSR_ESTAT, 0); // 清除中断状态

    // 使能全局中断
    uint64_t crmd = csr_read(LOONGARCH_CSR_CRMD);
    crmd |= CSR_CRMD_IE;
    csr_write(LOONGARCH_CSR_CRMD, crmd);
}

void irq_enable_line(uint32_t irq_line) {
    if (irq_line < 13) { // IS[12:0]
        uint64_t ecfg = csr_read(LOONGARCH_CSR_ECFG);
        ecfg |= (1UL << irq_line);
        csr_write(LOONGARCH_CSR_ECFG, ecfg);
    }
}

void irq_disable_line(uint32_t irq_line) {
    if (irq_line < 13) {
        uint64_t ecfg = csr_read(LOONGARCH_CSR_ECFG);
        ecfg &= ~(1UL << irq_line);
        csr_write(LOONGARCH_CSR_ECFG, ecfg);
    }
}
