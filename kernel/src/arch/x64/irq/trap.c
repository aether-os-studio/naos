#include <arch/arch.h>
#include <stdarg.h>
#include <mm/mm.h>
#include <drivers/kernel_logger.h>
#include <drivers/tty.h>
#include <task/task.h>
#include <mod/dlinker.h>
#include <mm/fault.h>

extern const uint64_t kallsyms_address[] __attribute__((weak));
extern const uint64_t kallsyms_num __attribute__((weak));
extern const uint64_t kallsyms_names_index[] __attribute__((weak));
extern const char *kallsyms_names __attribute__((weak));

void irq_init() {
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

int lookup_kallsyms(uint64_t addr, int level) {
    const char *str = (const char *)&kallsyms_names;

    uint64_t index = 0;
    for (index = 0; index < kallsyms_num - 1; ++index) {
        if (addr > kallsyms_address[index] &&
            addr <= kallsyms_address[index + 1])
            break;
    }

    if (index < kallsyms_num) {
        printk("function:%s() \t(+) %04d address:%#018lx\n",
               &str[kallsyms_names_index[index]],
               addr - kallsyms_address[index], addr);
        return 0;
    } else
        return -1;
}

#define TRACEBACK_MAX_DEPTH 32

void traceback(struct pt_regs *regs) {
    uint64_t *rbp = (uint64_t *)regs->rbp;
    uint64_t ret_addr = regs->rip;
    if (ret_addr < get_physical_memory_offset())
        goto check_user_fault;

    printk("======== Kernel traceback =======\n");
    for (int i = 0; i < TRACEBACK_MAX_DEPTH; ++i) {
        if (ret_addr < get_physical_memory_offset())
            break;

        if (lookup_kallsyms(ret_addr, i) != 0)
            break;

        if (!rbp || ((uint64_t)rbp < regs->rsp))
            break;

        ret_addr = *(rbp + 1);
        rbp = (uint64_t *)(*rbp);
        if ((uint64_t)rbp < get_physical_memory_offset())
            break;
    }
    printk("======== Kernel traceback end =======\n");

check_user_fault:
    if (current_task) {
        rb_node_t *node =
            rb_first(&current_task->arch_context->mm->task_vma_mgr.vma_tree);

        while (node) {
            vma_t *vma = rb_entry(node, vma_t, vm_rb);
            vfs_node_t vfs_node = vma->node;

            if (vma->vm_name) {
                if (ret_addr >= vma->vm_start && ret_addr <= vma->vm_end) {
                    printk("Fault in this vma: %s, vma->vm_start = %#018lx, "
                           "offset_in_vma = %#018lx\n",
                           vma->vm_name, vma->vm_start,
                           ret_addr - vma->vm_start);
                } else {
                    printk("Faulting task vma: %s, vma->vm_start = %#018lx\n",
                           vma->vm_name, vma->vm_start);
                }
            }

            node = rb_next(node);
        }
    }
}

extern int vsprintf(char *buf, const char *fmt, va_list args);

extern bool can_schedule;

spinlock_t dump_lock = SPIN_INIT;

extern tty_t *kernel_session;

void dump_regs(struct pt_regs *regs, const char *error_str, ...) {
    can_schedule = false;

    char old_mode = VT_AUTO;

    if (kernel_session) {
        old_mode = kernel_session->current_vt_mode.mode;
        kernel_session->current_vt_mode.mode = VT_AUTO;
    }

    spin_lock(&dump_lock);

    char buf[128];
    va_list args;
    va_start(args, error_str);
    vsprintf(buf, error_str, args);
    va_end(args);

    // printk("\033[0;0H");
    // printk("\033[2J");
    printk("%s\n", buf);

    traceback(regs);

    printk("current_task->pid = %d, current_task->name = %s\n",
           current_task->pid, current_task->name);

    printk("RIP = %#018lx\n", regs->rip);
    printk("RAX = %#018lx, RBX = %#018lx\n", regs->rax, regs->rbx);
    printk("RCX = %#018lx, RDX = %#018lx\n", regs->rcx, regs->rdx);
    printk("RDI = %#018lx, RSI = %#018lx\n", regs->rdi, regs->rsi);
    printk("RSP = %#018lx, RBP = %#018lx\n", regs->rsp, regs->rbp);
    printk("R08 = %#018lx, R09 = %#018lx\n", regs->r8, regs->r9);
    printk("R10 = %#018lx, R11 = %#018lx\n", regs->r10, regs->r11);
    printk("R12 = %#018lx, R13 = %#018lx\n", regs->r12, regs->r13);
    printk("R14 = %#018lx, R15 = %#018lx\n", regs->r14, regs->r15);

    if (kernel_session) {
        kernel_session->current_vt_mode.mode = old_mode;
    }

    spin_unlock(&dump_lock);
}

// 0 #DE 除法错误
void do_divide_error(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_divder_error(0)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 1 #DB 调试异常
void do_debug(struct pt_regs *regs, uint64_t error_code) { return; }

// 2 不可屏蔽中断
void do_nmi(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_nmi(2)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 3 #BP 断点异常
void do_int3(struct pt_regs *regs, uint64_t error_code) { return; }

// 4 #OF 溢出异常
void do_overflow(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_overflow(4)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 5 #BR 越界异常
void do_bounds(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_bounds(5)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 6 #UD 无效/未定义的机器码
void do_undefined_opcode(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_undefined_opcode(6)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 7 #NM 设备异常（FPU不存在）
void do_dev_not_avaliable(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_dev_not_avaliable(7)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 8 #DF 双重错误
void do_double_fault(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_double_fault(8)");

    while (1)
        asm volatile("hlt");
}

// 9 协处理器越界（保留）
void do_coprocessor_segment_overrun(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_coprocessor_segment_overrun(9)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 10 #TS 无效的TSS段
void do_invalid_TSS(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_invalid_TSS(10)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 11 #NP 段不存在
void do_segment_not_exists(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_segment_not_exists(11");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 12 #SS SS段错误
void do_stack_segment_fault(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_stack_segment_fault(12)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 13 #GP 通用保护性异常
void do_general_protection(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_general_protection(13)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 14 #PF 页故障
void do_page_fault(struct pt_regs *regs, uint64_t error_code) {
    uint64_t cr2 = 0;
    // 先保存cr2寄存器的值，避免由于再次触发页故障而丢失值
    // cr2存储着触发异常的线性地址
    asm volatile("movq %%cr2, %0" : "=r"(cr2)::"memory");

    if (handle_page_fault(current_task, cr2) == PF_RES_OK)
        return;

    (void)error_code;
    dump_regs(regs, "do_page_fault(14) cr2 = %#018lx", cr2);

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 15 Intel保留，请勿使用

// 16 #MF x87FPU错误
void do_x87_FPU_error(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_x87_FPU_error(16)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 17 #AC 对齐检测
void do_alignment_check(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_alignment_check(17)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 18 #MC 机器检测
void do_machine_check(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_machine_check(18)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 19 #XM SIMD浮点异常
void do_SIMD_exception(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_SIMD_exception(19)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

// 20 #VE 虚拟化异常
void do_virtualization_exception(struct pt_regs *regs, uint64_t error_code) {
    (void)error_code;
    dump_regs(regs, "do_virtualization_exception(20)");

    if ((regs->cs & 3) == 3) {
        can_schedule = true;
        task_exit(128 + SIGSEGV);
        return;
    }

    while (1)
        asm volatile("hlt");
}

void arch_make_trap() { asm volatile("int %0" ::"i"(1)); }
