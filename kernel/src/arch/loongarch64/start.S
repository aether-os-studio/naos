.global _start
_start:
    bl trap_init

    b kmain

.global _ap_start
_ap_start:
    bl trap_init

    b ap_kmain
