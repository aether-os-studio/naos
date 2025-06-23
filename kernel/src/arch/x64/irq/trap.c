#include <arch/arch.h>
#include <stdarg.h>
#include <mm/mm.h>
#include <drivers/kernel_logger.h>
#include <task/task.h>

void irq_init()
{
    gdtidt_setup();

    set_trap_gate(0, 0, divide_error);
    set_trap_gate(1, 0, debug);
    set_intr_gate(2, 0, nmi);
    set_system_trap_gate(3, 0, int3);
    set_system_trap_gate(4, 0, overflow);
    set_system_trap_gate(5, 0, bounds);
    set_trap_gate(6, 0, undefined_opcode);
    set_trap_gate(7, 0, dev_not_avaliable);
    set_trap_gate(8, 0, double_fault);
    set_trap_gate(9, 0, coprocessor_segment_overrun);
    set_trap_gate(10, 0, invalid_TSS);
    set_trap_gate(11, 0, segment_not_exists);
    set_trap_gate(12, 0, stack_segment_fault);
    set_trap_gate(13, 0, general_protection);
    set_trap_gate(14, 0, page_fault);
    // 中断号15由Intel保留，不能使用
    set_trap_gate(16, 0, x87_FPU_error);
    set_trap_gate(17, 0, alignment_check);
    set_trap_gate(18, 0, machine_check);
    set_trap_gate(19, 0, SIMD_exception);
    set_trap_gate(20, 0, virtualization_exception);
}

extern int vsprintf(char *buf, const char *fmt, va_list args);

extern bool can_schedule;

void dump_regs(struct pt_regs *regs, const char *error_str, ...)
{
    can_schedule = false;

    char buf[128];
    va_list args;
    va_start(args, error_str);
    vsprintf(buf, error_str, args);
    va_end(args);

    // printk("\033[0;0H");
    // printk("\033[2J");
    printk("%s\n", buf);

    printk("current_task->name = %s\n", current_task->name);

    printk("RIP = %#018lx\n", regs->rip);
    printk("RAX = %#018lx, RBX = %#018lx\n", regs->rax, regs->rbx);
    printk("RCX = %#018lx, RDX = %#018lx\n", regs->rcx, regs->rdx);
    printk("RDI = %#018lx, RSI = %#018lx\n", regs->rdi, regs->rsi);
    printk("RSP = %#018lx, RBP = %#018lx\n", regs->rsp, regs->rbp);
    printk("R08 = %#018lx, R09 = %#018lx\n", regs->r8, regs->r9);
    printk("R10 = %#018lx, R11 = %#018lx\n", regs->r10, regs->r11);
    printk("R12 = %#018lx, R13 = %#018lx\n", regs->r12, regs->r13);
    printk("R14 = %#018lx, R15 = %#018lx\n", regs->r14, regs->r15);
}

// 0 #DE 除法错误
void do_divide_error(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_divder_error(0)");

    if (regs->rsp <= get_physical_memory_offset())
    {
        can_schedule = true;
        task_exit(-EFAULT);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 1 #DB 调试异常
void do_debug(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_debug(1)");

    while (1)
        asm volatile("hlt");
}

// 2 不可屏蔽中断
void do_nmi(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_nmi(2)");

    while (1)
        asm volatile("hlt");
}

// 3 #BP 断点异常
void do_int3(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_int3(3)");

    return;
}

// 4 #OF 溢出异常
void do_overflow(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_overflow(4)");

    while (1)
        asm volatile("hlt");
}

// 5 #BR 越界异常
void do_bounds(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_bounds(5)");

    while (1)
        asm volatile("hlt");
}

// 6 #UD 无效/未定义的机器码
void do_undefined_opcode(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_undefined_opcode(6)");

    if (regs->rsp <= get_physical_memory_offset())
    {
        can_schedule = true;
        task_exit(-EFAULT);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 7 #NM 设备异常（FPU不存在）
void do_dev_not_avaliable(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_dev_not_avaliable(7)");

    while (1)
        asm volatile("hlt");
}

// 8 #DF 双重错误
void do_double_fault(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_double_fault(8)");

    while (1)
        asm volatile("hlt");
}

// 9 协处理器越界（保留）
void do_coprocessor_segment_overrun(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_coprocessor_segment_overrun(9)");

    while (1)
        asm volatile("hlt");
}

// 10 #TS 无效的TSS段
void do_invalid_TSS(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_invalid_TSS(10)");

    if (regs->rsp <= get_physical_memory_offset())
    {
        can_schedule = true;
        task_exit(-EFAULT);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 11 #NP 段不存在
void do_segment_not_exists(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_segment_not_exists(11");

    if (regs->rsp <= get_physical_memory_offset())
    {
        can_schedule = true;
        task_exit(-EFAULT);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 12 #SS SS段错误
void do_stack_segment_fault(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_stack_segment_fault(12)");

    while (1)
        asm volatile("hlt");
}

// 13 #GP 通用保护性异常
void do_general_protection(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_general_protection(13)");

    if (regs->rsp <= get_physical_memory_offset())
    {
        can_schedule = true;
        task_exit(-EFAULT);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 14 #PF 页故障
void do_page_fault(struct pt_regs *regs, uint64_t error_code)
{
    uint64_t cr2 = 0;
    // 先保存cr2寄存器的值，避免由于再次触发页故障而丢失值
    // cr2存储着触发异常的线性地址
    asm volatile("movq %%cr2, %0"
                 : "=r"(cr2)::"memory");

    (void)error_code;
    dump_regs(regs, "do_page_fault(14) cr2 = %#018lx", cr2);

    if (regs->rsp <= get_physical_memory_offset())
    {
        can_schedule = true;
        task_exit(-EFAULT);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 15 Intel保留，请勿使用

// 16 #MF x87FPU错误
void do_x87_FPU_error(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_x87_FPU_error(16)");

    while (1)
        asm volatile("hlt");
}

// 17 #AC 对齐检测
void do_alignment_check(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_alignment_check(17)");

    while (1)
        asm volatile("hlt");
}

// 18 #MC 机器检测
void do_machine_check(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_machine_check(18)");

    while (1)
        asm volatile("hlt");
}

// 19 #XM SIMD浮点异常
void do_SIMD_exception(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_SIMD_exception(19)");

    while (1)
        asm volatile("hlt");
}

// 20 #VE 虚拟化异常
void do_virtualization_exception(struct pt_regs *regs, uint64_t error_code)
{
    (void)error_code;
    dump_regs(regs, "do_virtualization_exception(20)");

    while (1)
        asm volatile("hlt");
}
