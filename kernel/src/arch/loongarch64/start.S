.global _start
_start:
    csrrd $t0, 0x2
    ori $t0, $t0, 0x2
    csrwr $t0, 0x2

    b kmain
