.global ret_from_fork
ret_from_fork:
    subq $0xc0, %rsp
    call before_ret_from_fork
    addq $0xc0, %rsp
    jmp ret_from_syscall
