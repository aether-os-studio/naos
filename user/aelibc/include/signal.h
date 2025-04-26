#pragma once

#include <stdint.h>

enum SIGNAL
{
    SIGHUP = 1,   // 挂断控制终端或进程
    SIGINT,       // 来自键盘的中断
    SIGQUIT,      // 来自键盘的退出
    SIGILL,       // 非法指令
    SIGTRAP,      // 跟踪断点
    SIGABRT,      // 异常结束
    SIGIOT = 6,   // 异常结束
    SIGUNUSED,    // 没有使用
    SIGFPE,       // 协处理器出错
    SIGKILL = 9,  // 强迫进程终止
    SIGUSR1,      // 用户信号 1，进程可使用
    SIGSEGV,      // 无效内存引用
    SIGUSR2,      // 用户信号 2，进程可使用
    SIGPIPE,      // 管道写出错，无读者
    SIGALRM,      // 实时定时器报警
    SIGTERM = 15, // 进程终止
    SIGSTKFLT,    // 栈出错（协处理器）
    SIGCHLD,      // 子进程停止或被终止
    SIGCONT,      // 恢复进程继续执行
    SIGSTOP,      // 停止进程的执行
    SIGTSTP,      // tty 发出停止进程，可忽略
    SIGTTIN,      // 后台进程请求输入
    SIGTTOU = 22, // 后台进程请求输出
};

int ssetmask(int mask);
int signal(int sig, uint64_t handler);
