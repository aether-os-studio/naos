.global ret_from_fork
ret_from_fork:
    cli
    call before_ret_from_fork
    jmp ret_from_syscall
