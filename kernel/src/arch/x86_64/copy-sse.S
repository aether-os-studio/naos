.section .text
.global fast_copy_16
.type fast_copy_16, @function

fast_copy_16:
    jmp memcpy
