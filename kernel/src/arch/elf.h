#pragma once

#include <libs/klibc.h>

#define EI_NIDENT 16

typedef struct
{
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
} Elf64_Ehdr;

typedef struct
{
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6
#define PT_TLS 7
#define PT_NUM 8
#define PT_LOOS 1610612736
#define PT_GNU_EH_FRAME 1685382480
#define PT_GNU_STACK 1685382481
#define PT_GNU_RELRO 1685382482
#define PT_LOSUNW 1879048186
#define PT_SUNWBSS 1879048186
#define PT_SUNWSTACK 1879048187
#define PT_HISUNW 1879048191
#define PT_HIOS 1879048191
#define PT_LOPROC 1879048192
#define PT_HIPROC 2147483647

#define PF_EXEC 1
