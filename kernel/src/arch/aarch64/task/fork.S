.global ret_from_fork
ret_from_fork:
    bl before_ret_from_fork
    b arch_context_switch_exit

