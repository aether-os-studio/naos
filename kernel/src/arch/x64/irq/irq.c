#include <libs/klibc.h>
#include <arch/arch.h>

void arch_enable_interrupt() { open_interrupt; }

void arch_disable_interrupt() { close_interrupt; }

bool arch_interrupt_enabled() {
    long flags;
    asm volatile("pushfq\n\t"
                 "pop %0\n\t"
                 : "=r"(flags)
                 :
                 : "memory");
    return !!(flags & (1 << 9));
}

// 保存函数调用现场的寄存器
#define SAVE_ALL_REGS                                                          \
    "cld; \n\t"                                                                \
    "pushq $0;    \n\t"                                                        \
    "subq $0x8, %rsp;    \n\t"                                                 \
    "pushq %rax;     \n\t"                                                     \
    "pushq %rbp;     \n\t"                                                     \
    "pushq %rdi;     \n\t"                                                     \
    "pushq %rsi;     \n\t"                                                     \
    "pushq %rdx;     \n\t"                                                     \
    "pushq %rcx;     \n\t"                                                     \
    "pushq %rbx;     \n\t"                                                     \
    "pushq %r8 ;    \n\t"                                                      \
    "pushq %r9 ;    \n\t"                                                      \
    "pushq %r10;     \n\t"                                                     \
    "pushq %r11;     \n\t"                                                     \
    "pushq %r12;     \n\t"                                                     \
    "pushq %r13;     \n\t"                                                     \
    "pushq %r14;     \n\t"                                                     \
    "pushq %r15;     \n\t"

// 定义IRQ处理函数的名字格式：IRQ+中断号+interrupt
#define IRQ_NAME2(name1) name1##interrupt(void)
#define IRQ_NAME(number) IRQ_NAME2(IRQ##number)

// 构造中断entry
// 为了复用返回函数的代码，需要压入一个错误码0

#define BUILD_IRQ(number)                                                      \
    extern void IRQ_NAME(number);                                              \
    asm(".section .text\n\t" SYMBOL_NAME_STR(IRQ) #number                      \
        "interrupt:\n\t"                                                       \
        "cli\n\t"                                                              \
        "pushq $0x00\n\t" SAVE_ALL_REGS "movq %rsp, %rdi\n\t"                  \
        "leaq ret_from_intr(%rip), %rax\n\t"                                   \
        "pushq %rax \n\t"                                                      \
        "movq	$" #number ", %rsi\n\t"                                        \
        "jmp do_irq\n\t");

// 构造中断入口
BUILD_IRQ(0x20);
BUILD_IRQ(0x21);
BUILD_IRQ(0x22);
BUILD_IRQ(0x23);
BUILD_IRQ(0x24);
BUILD_IRQ(0x25);
BUILD_IRQ(0x26);
BUILD_IRQ(0x27);
BUILD_IRQ(0x28);
BUILD_IRQ(0x29);
BUILD_IRQ(0x2a);
BUILD_IRQ(0x2b);
BUILD_IRQ(0x2c);
BUILD_IRQ(0x2d);
BUILD_IRQ(0x2e);
BUILD_IRQ(0x2f);
BUILD_IRQ(0x30);
BUILD_IRQ(0x31);
BUILD_IRQ(0x32);
BUILD_IRQ(0x33);
BUILD_IRQ(0x34);
BUILD_IRQ(0x35);
BUILD_IRQ(0x36);
BUILD_IRQ(0x37);
BUILD_IRQ(0x38);
BUILD_IRQ(0x39);
BUILD_IRQ(0x3a);
BUILD_IRQ(0x3b);
BUILD_IRQ(0x3c);
BUILD_IRQ(0x3d);
BUILD_IRQ(0x3e);
BUILD_IRQ(0x3f);
BUILD_IRQ(0x40);
BUILD_IRQ(0x41);
BUILD_IRQ(0x42);
BUILD_IRQ(0x43);
BUILD_IRQ(0x44);
BUILD_IRQ(0x45);
BUILD_IRQ(0x46);
BUILD_IRQ(0x47);
BUILD_IRQ(0x48);
BUILD_IRQ(0x49);
BUILD_IRQ(0x4a);
BUILD_IRQ(0x4b);
BUILD_IRQ(0x4c);
BUILD_IRQ(0x4d);
BUILD_IRQ(0x4e);
BUILD_IRQ(0x4f);

// 初始化中断数组
void (*interrupt_table[])(void) = {
    IRQ0x20interrupt, IRQ0x21interrupt, IRQ0x22interrupt, IRQ0x23interrupt,
    IRQ0x24interrupt, IRQ0x25interrupt, IRQ0x26interrupt, IRQ0x27interrupt,
    IRQ0x28interrupt, IRQ0x29interrupt, IRQ0x2ainterrupt, IRQ0x2binterrupt,
    IRQ0x2cinterrupt, IRQ0x2dinterrupt, IRQ0x2einterrupt, IRQ0x2finterrupt,
    IRQ0x30interrupt, IRQ0x31interrupt, IRQ0x32interrupt, IRQ0x33interrupt,
    IRQ0x34interrupt, IRQ0x35interrupt, IRQ0x36interrupt, IRQ0x37interrupt,
    IRQ0x38interrupt, IRQ0x39interrupt, IRQ0x3ainterrupt, IRQ0x3binterrupt,
    IRQ0x3cinterrupt, IRQ0x3dinterrupt, IRQ0x3einterrupt, IRQ0x3finterrupt,
    IRQ0x40interrupt, IRQ0x41interrupt, IRQ0x42interrupt, IRQ0x43interrupt,
    IRQ0x44interrupt, IRQ0x45interrupt, IRQ0x46interrupt, IRQ0x47interrupt,
    IRQ0x48interrupt, IRQ0x49interrupt, IRQ0x4ainterrupt, IRQ0x4binterrupt,
    IRQ0x4cinterrupt, IRQ0x4dinterrupt, IRQ0x4einterrupt, IRQ0x4finterrupt,
};

void generic_interrupt_table_init_early() {
    for (int i = 0x20; i < 0x50; ++i) {
        set_intr_gate(i, 0, interrupt_table[i - 0x20]);
    }
}
