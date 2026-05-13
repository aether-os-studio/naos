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
BUILD_IRQ(0x50);
BUILD_IRQ(0x51);
BUILD_IRQ(0x52);
BUILD_IRQ(0x53);
BUILD_IRQ(0x54);
BUILD_IRQ(0x55);
BUILD_IRQ(0x56);
BUILD_IRQ(0x57);
BUILD_IRQ(0x58);
BUILD_IRQ(0x59);
BUILD_IRQ(0x5a);
BUILD_IRQ(0x5b);
BUILD_IRQ(0x5c);
BUILD_IRQ(0x5d);
BUILD_IRQ(0x5e);
BUILD_IRQ(0x5f);
BUILD_IRQ(0x60);
BUILD_IRQ(0x61);
BUILD_IRQ(0x62);
BUILD_IRQ(0x63);
BUILD_IRQ(0x64);
BUILD_IRQ(0x65);
BUILD_IRQ(0x66);
BUILD_IRQ(0x67);
BUILD_IRQ(0x68);
BUILD_IRQ(0x69);
BUILD_IRQ(0x6a);
BUILD_IRQ(0x6b);
BUILD_IRQ(0x6c);
BUILD_IRQ(0x6d);
BUILD_IRQ(0x6e);
BUILD_IRQ(0x6f);
BUILD_IRQ(0x70);
BUILD_IRQ(0x71);
BUILD_IRQ(0x72);
BUILD_IRQ(0x73);
BUILD_IRQ(0x74);
BUILD_IRQ(0x75);
BUILD_IRQ(0x76);
BUILD_IRQ(0x77);
BUILD_IRQ(0x78);
BUILD_IRQ(0x79);
BUILD_IRQ(0x7a);
BUILD_IRQ(0x7b);
BUILD_IRQ(0x7c);
BUILD_IRQ(0x7d);
BUILD_IRQ(0x7e);
BUILD_IRQ(0x7f);
BUILD_IRQ(0x80);
BUILD_IRQ(0x81);
BUILD_IRQ(0x82);
BUILD_IRQ(0x83);
BUILD_IRQ(0x84);
BUILD_IRQ(0x85);
BUILD_IRQ(0x86);
BUILD_IRQ(0x87);
BUILD_IRQ(0x88);
BUILD_IRQ(0x89);
BUILD_IRQ(0x8a);
BUILD_IRQ(0x8b);
BUILD_IRQ(0x8c);
BUILD_IRQ(0x8d);
BUILD_IRQ(0x8e);
BUILD_IRQ(0x8f);
BUILD_IRQ(0x90);
BUILD_IRQ(0x91);
BUILD_IRQ(0x92);
BUILD_IRQ(0x93);
BUILD_IRQ(0x94);
BUILD_IRQ(0x95);
BUILD_IRQ(0x96);
BUILD_IRQ(0x97);
BUILD_IRQ(0x98);
BUILD_IRQ(0x99);
BUILD_IRQ(0x9a);
BUILD_IRQ(0x9b);
BUILD_IRQ(0x9c);
BUILD_IRQ(0x9d);
BUILD_IRQ(0x9e);
BUILD_IRQ(0x9f);
BUILD_IRQ(0xa0);
BUILD_IRQ(0xa1);
BUILD_IRQ(0xa2);
BUILD_IRQ(0xa3);
BUILD_IRQ(0xa4);
BUILD_IRQ(0xa5);
BUILD_IRQ(0xa6);
BUILD_IRQ(0xa7);
BUILD_IRQ(0xa8);
BUILD_IRQ(0xa9);
BUILD_IRQ(0xaa);
BUILD_IRQ(0xab);
BUILD_IRQ(0xac);
BUILD_IRQ(0xad);
BUILD_IRQ(0xae);
BUILD_IRQ(0xaf);
BUILD_IRQ(0xb0);
BUILD_IRQ(0xb1);
BUILD_IRQ(0xb2);
BUILD_IRQ(0xb3);
BUILD_IRQ(0xb4);
BUILD_IRQ(0xb5);
BUILD_IRQ(0xb6);
BUILD_IRQ(0xb7);
BUILD_IRQ(0xb8);
BUILD_IRQ(0xb9);
BUILD_IRQ(0xba);
BUILD_IRQ(0xbb);
BUILD_IRQ(0xbc);
BUILD_IRQ(0xbd);
BUILD_IRQ(0xbe);
BUILD_IRQ(0xbf);
BUILD_IRQ(0xc0);
BUILD_IRQ(0xc1);
BUILD_IRQ(0xc2);
BUILD_IRQ(0xc3);
BUILD_IRQ(0xc4);
BUILD_IRQ(0xc5);
BUILD_IRQ(0xc6);
BUILD_IRQ(0xc7);
BUILD_IRQ(0xc8);
BUILD_IRQ(0xc9);
BUILD_IRQ(0xca);
BUILD_IRQ(0xcb);
BUILD_IRQ(0xcc);
BUILD_IRQ(0xcd);
BUILD_IRQ(0xce);
BUILD_IRQ(0xcf);
BUILD_IRQ(0xd0);
BUILD_IRQ(0xd1);
BUILD_IRQ(0xd2);
BUILD_IRQ(0xd3);
BUILD_IRQ(0xd4);
BUILD_IRQ(0xd5);
BUILD_IRQ(0xd6);
BUILD_IRQ(0xd7);
BUILD_IRQ(0xd8);
BUILD_IRQ(0xd9);
BUILD_IRQ(0xda);
BUILD_IRQ(0xdb);
BUILD_IRQ(0xdc);
BUILD_IRQ(0xdd);
BUILD_IRQ(0xde);
BUILD_IRQ(0xdf);
BUILD_IRQ(0xe0);
BUILD_IRQ(0xe1);
BUILD_IRQ(0xe2);
BUILD_IRQ(0xe3);
BUILD_IRQ(0xe4);
BUILD_IRQ(0xe5);
BUILD_IRQ(0xe6);
BUILD_IRQ(0xe7);
BUILD_IRQ(0xe8);
BUILD_IRQ(0xe9);
BUILD_IRQ(0xea);
BUILD_IRQ(0xeb);
BUILD_IRQ(0xec);
BUILD_IRQ(0xed);
BUILD_IRQ(0xee);
BUILD_IRQ(0xef);
BUILD_IRQ(0xf0);
BUILD_IRQ(0xf1);
BUILD_IRQ(0xf2);
BUILD_IRQ(0xf3);
BUILD_IRQ(0xf4);
BUILD_IRQ(0xf5);
BUILD_IRQ(0xf6);
BUILD_IRQ(0xf7);
BUILD_IRQ(0xf8);
BUILD_IRQ(0xf9);
BUILD_IRQ(0xfa);
BUILD_IRQ(0xfb);
BUILD_IRQ(0xfc);
BUILD_IRQ(0xfd);
BUILD_IRQ(0xfe);
BUILD_IRQ(0xff);

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

    IRQ0x50interrupt, IRQ0x51interrupt, IRQ0x52interrupt, IRQ0x53interrupt,
    IRQ0x54interrupt, IRQ0x55interrupt, IRQ0x56interrupt, IRQ0x57interrupt,
    IRQ0x58interrupt, IRQ0x59interrupt, IRQ0x5ainterrupt, IRQ0x5binterrupt,
    IRQ0x5cinterrupt, IRQ0x5dinterrupt, IRQ0x5einterrupt, IRQ0x5finterrupt,

    IRQ0x60interrupt, IRQ0x61interrupt, IRQ0x62interrupt, IRQ0x63interrupt,
    IRQ0x64interrupt, IRQ0x65interrupt, IRQ0x66interrupt, IRQ0x67interrupt,
    IRQ0x68interrupt, IRQ0x69interrupt, IRQ0x6ainterrupt, IRQ0x6binterrupt,
    IRQ0x6cinterrupt, IRQ0x6dinterrupt, IRQ0x6einterrupt, IRQ0x6finterrupt,

    IRQ0x70interrupt, IRQ0x71interrupt, IRQ0x72interrupt, IRQ0x73interrupt,
    IRQ0x74interrupt, IRQ0x75interrupt, IRQ0x76interrupt, IRQ0x77interrupt,
    IRQ0x78interrupt, IRQ0x79interrupt, IRQ0x7ainterrupt, IRQ0x7binterrupt,
    IRQ0x7cinterrupt, IRQ0x7dinterrupt, IRQ0x7einterrupt, IRQ0x7finterrupt,

    IRQ0x80interrupt, IRQ0x81interrupt, IRQ0x82interrupt, IRQ0x83interrupt,
    IRQ0x84interrupt, IRQ0x85interrupt, IRQ0x86interrupt, IRQ0x87interrupt,
    IRQ0x88interrupt, IRQ0x89interrupt, IRQ0x8ainterrupt, IRQ0x8binterrupt,
    IRQ0x8cinterrupt, IRQ0x8dinterrupt, IRQ0x8einterrupt, IRQ0x8finterrupt,

    IRQ0x90interrupt, IRQ0x91interrupt, IRQ0x92interrupt, IRQ0x93interrupt,
    IRQ0x94interrupt, IRQ0x95interrupt, IRQ0x96interrupt, IRQ0x97interrupt,
    IRQ0x98interrupt, IRQ0x99interrupt, IRQ0x9ainterrupt, IRQ0x9binterrupt,
    IRQ0x9cinterrupt, IRQ0x9dinterrupt, IRQ0x9einterrupt, IRQ0x9finterrupt,

    IRQ0xa0interrupt, IRQ0xa1interrupt, IRQ0xa2interrupt, IRQ0xa3interrupt,
    IRQ0xa4interrupt, IRQ0xa5interrupt, IRQ0xa6interrupt, IRQ0xa7interrupt,
    IRQ0xa8interrupt, IRQ0xa9interrupt, IRQ0xaainterrupt, IRQ0xabinterrupt,
    IRQ0xacinterrupt, IRQ0xadinterrupt, IRQ0xaeinterrupt, IRQ0xafinterrupt,

    IRQ0xb0interrupt, IRQ0xb1interrupt, IRQ0xb2interrupt, IRQ0xb3interrupt,
    IRQ0xb4interrupt, IRQ0xb5interrupt, IRQ0xb6interrupt, IRQ0xb7interrupt,
    IRQ0xb8interrupt, IRQ0xb9interrupt, IRQ0xbainterrupt, IRQ0xbbinterrupt,
    IRQ0xbcinterrupt, IRQ0xbdinterrupt, IRQ0xbeinterrupt, IRQ0xbfinterrupt,

    IRQ0xc0interrupt, IRQ0xc1interrupt, IRQ0xc2interrupt, IRQ0xc3interrupt,
    IRQ0xc4interrupt, IRQ0xc5interrupt, IRQ0xc6interrupt, IRQ0xc7interrupt,
    IRQ0xc8interrupt, IRQ0xc9interrupt, IRQ0xcainterrupt, IRQ0xcbinterrupt,
    IRQ0xccinterrupt, IRQ0xcdinterrupt, IRQ0xceinterrupt, IRQ0xcfinterrupt,

    IRQ0xd0interrupt, IRQ0xd1interrupt, IRQ0xd2interrupt, IRQ0xd3interrupt,
    IRQ0xd4interrupt, IRQ0xd5interrupt, IRQ0xd6interrupt, IRQ0xd7interrupt,
    IRQ0xd8interrupt, IRQ0xd9interrupt, IRQ0xdainterrupt, IRQ0xdbinterrupt,
    IRQ0xdcinterrupt, IRQ0xddinterrupt, IRQ0xdeinterrupt, IRQ0xdfinterrupt,

    IRQ0xe0interrupt, IRQ0xe1interrupt, IRQ0xe2interrupt, IRQ0xe3interrupt,
    IRQ0xe4interrupt, IRQ0xe5interrupt, IRQ0xe6interrupt, IRQ0xe7interrupt,
    IRQ0xe8interrupt, IRQ0xe9interrupt, IRQ0xeainterrupt, IRQ0xebinterrupt,
    IRQ0xecinterrupt, IRQ0xedinterrupt, IRQ0xeeinterrupt, IRQ0xefinterrupt,

    IRQ0xf0interrupt, IRQ0xf1interrupt, IRQ0xf2interrupt, IRQ0xf3interrupt,
    IRQ0xf4interrupt, IRQ0xf5interrupt, IRQ0xf6interrupt, IRQ0xf7interrupt,
    IRQ0xf8interrupt, IRQ0xf9interrupt, IRQ0xfainterrupt, IRQ0xfbinterrupt,
    IRQ0xfcinterrupt, IRQ0xfdinterrupt, IRQ0xfeinterrupt, IRQ0xffinterrupt,
};

void generic_interrupt_table_init_early() {
    for (int i = 0x20; i < 0x100; ++i) {
        set_intr_gate(i, 0, interrupt_table[i - 0x20]);
    }
}
