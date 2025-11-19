#pragma once

#include <arch/loongarch64/irq/ptrace.h>

// 异常码
#define EXCCODE_INT 0x0   // 中断
#define EXCCODE_PIL 0x1   // 页无效异常(Load)
#define EXCCODE_PIS 0x2   // 页无效异常(Store)
#define EXCCODE_PIF 0x3   // 页无效异常(Fetch)
#define EXCCODE_PME 0x4   // 页修改异常
#define EXCCODE_PPI 0x7   // 页特权等级异常
#define EXCCODE_ADEF 0x8  // 取指地址错误
#define EXCCODE_ADEM 0x9  // 访存地址错误
#define EXCCODE_SYS 0xb   // 系统调用
#define EXCCODE_BRK 0xc   // 断点
#define EXCCODE_INE 0xd   // 指令不存在
#define EXCCODE_IPE 0xe   // 指令特权等级错误
#define EXCCODE_TLBR 0x3f // TLB重填

// 异常处理函数类型
typedef void (*trap_handler_t)(struct pt_regs *regs);

// 函数声明
void trap_init();
void trap_handle_c(struct pt_regs *regs);
