# pl_readline

一个简单的键盘输入库，支持方向键及 tab 补全。

## Example

See `example/echo.c` for details.

**NOTE**: This example is for Linux only.

## Feature

- [x] 自定义提示符
- [x] 左右方向键移动光标
- [x] 上下方向键翻看历史命令
- [x] 支持 tab 补全
- [ ] 获取终端大小并手动维护换行

## Why to write pl_readline

因为我不想依赖于系统的 readline 库，而是自己实现一个简单的键盘输入库。在写一个裸机程序时，用这个库可以节省很多时间。当然，你也可以用这个库来为你的操作系统实现 shell，因为这个库是以 MIT 协议发布的。

## How to port to other system

### Basic support

终端需要支持 vt100 控制字符，能输出字符和读取输入字符，输出字符和输入字符需要没有缓冲，你可以在 getch 中刷新缓冲。

### Extended support

实现 Plant OS 的 vt100 扩展功能：`\x1b[C`向右到顶时会自动换行、`\x1b[D`向左到底时会自动换行，这样可以暂时支持多行

### General explanation

如果你的终端没有 vt100 支持，可以搭配[os-terminal](https://github.com/plos-clan/libos-terminal)使用，效果也很不错。

## Contribution

本库支持的功能还不完整，欢迎 PR。

如果有任何 bug，请在 issues 中提出。

**不接受新 feature 的 issue，但接受 PR**

但如果是下面的问题，将不会答复：

- linux 上无法多行。

发送 issue 你可能需要知道的：遇到 bug 请讲明白复现步骤，否则很难帮你解决。

## Additional

**HAVE FUN! 祝你玩的开心！**