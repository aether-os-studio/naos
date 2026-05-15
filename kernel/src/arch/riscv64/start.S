#ifdef __sbi__
.section .boot
#elifdef __limine__
.section .text
#else
#error "unknown boot protocol for riscv64"
#endif

.global _start
_start:
#ifdef __sbi__
    tail open_sbi_start
#elifdef __limine__
    tail kmain
#else
#error "unknown boot protocol for riscv64"
#endif
