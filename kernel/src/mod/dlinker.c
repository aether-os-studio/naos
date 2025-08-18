#include "dlinker.h"
#include <mm/mm.h>
#include <drivers/kernel_logger.h>

uint64_t kernel_modules_load_offset = 0;

extern dlfunc_t __ksymtab_start[]; // .ksymtab section
extern dlfunc_t __ksymtab_end[];
size_t dlfunc_count = 0;

dlfunc_t __printf = {.name = "printf", .addr = (void *)printk};

void load_segment(Elf64_Phdr *phdr, void *elf, uint64_t *directory,
                  uint64_t offset, uint64_t *load_start)
{
    size_t hi = PADDING_UP(phdr->p_paddr + phdr->p_memsz, 0x1000) + offset;
    size_t lo = PADDING_DOWN(phdr->p_paddr, 0x1000) + offset;
    if (load_start != NULL)
    {
        if (lo < *load_start)
        {
            *load_start = lo;
        }
    }
    uint64_t flags = PT_FLAG_R | PT_FLAG_W;

    map_page_range(directory, lo, 0, hi - lo, (phdr->p_flags & PF_X) ? (PT_FLAG_X | flags) : flags);

    uint64_t p_vaddr = (uint64_t)phdr->p_vaddr + offset;
    uint64_t p_filesz = (uint64_t)phdr->p_filesz;
    uint64_t p_memsz = (uint64_t)phdr->p_memsz;
    uint64_t physaddr_in_directory = translate_address(directory, p_vaddr);
    memcpy((void *)phys_to_virt(physaddr_in_directory), elf + phdr->p_offset, p_memsz);

    if (p_memsz > p_filesz)
    {
        memset((void *)(p_vaddr + p_filesz), 0, p_memsz - p_filesz);
    }
}

bool mmap_phdr_segment(Elf64_Ehdr *ehdr, Elf64_Phdr *phdrs, uint64_t *directory, uint64_t offset, uint64_t *load_start, uint64_t *load_size)
{
    size_t i = 0;
    while (i < ehdr->e_phnum && phdrs[i].p_type != PT_LOAD)
    {
        i++;
    }

    if (i == ehdr->e_phnum)
    {
        return false;
    }

    uint64_t load_min = 0xffffffffffffffff;
    uint64_t load_max = 0x0000000000000000;

    for (i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdrs[i].p_type == PT_LOAD)
        {
            load_segment(&phdrs[i], (void *)ehdr, directory, offset, load_start);
            if (phdrs[i].p_vaddr + offset + phdrs[i].p_memsz > load_max)
                load_max = phdrs[i].p_vaddr + offset + phdrs[i].p_memsz;
            if (phdrs[i].p_vaddr + offset < load_min)
                load_min = phdrs[i].p_vaddr + offset;
        }
    }

    if (load_size)
    {
        *load_size = load_max - load_min;
    }

    return true;
}

void *resolve_symbol(Elf64_Sym *symtab, uint32_t sym_idx)
{
    return (void *)symtab[sym_idx].st_value;
}

bool handle_relocations(Elf64_Rela *rela_start, Elf64_Sym *symtab, char *strtab, size_t jmprel_sz,
                        uint64_t offset)
{
    Elf64_Rela *rela_plt = rela_start;
    size_t rela_count = jmprel_sz / sizeof(Elf64_Rela);

    for (size_t i = 0; i < rela_count; i++)
    {
        Elf64_Rela *rela = &rela_plt[i];
        Elf64_Sym *sym = &symtab[ELF64_R_SYM(rela->r_info)];
        char *sym_name = &strtab[sym->st_name];
        dlfunc_t *func = find_func(sym_name);
        uint64_t *target_addr = (uint64_t *)(rela->r_offset + offset);
        if (func != NULL)
        {
            *target_addr = (uint64_t)func->addr;
        }
        else
        {
            printk("Failed relocating %s at %p\n", sym_name, rela->r_offset + offset);
        }
    }
    return true;
}

void *find_symbol_address(const char *symbol_name, Elf64_Ehdr *ehdr, uint64_t offset)
{
    if (symbol_name == NULL || ehdr == NULL)
        return NULL;

    Elf64_Sym *symtab = NULL;
    char *strtab = NULL;

    Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)ehdr + ehdr->e_shoff);
    char *shstrtab = (char *)ehdr + shdrs[ehdr->e_shstrndx].sh_offset;

    size_t symtabsz = 0;

    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        if (shdrs[i].sh_type == SHT_SYMTAB)
        {
            symtab = (Elf64_Sym *)((char *)ehdr + shdrs[i].sh_offset);
            symtabsz = shdrs[i].sh_size;
            strtab = (char *)ehdr + shdrs[shdrs[i].sh_link].sh_offset;
            break;
        }
    }

    size_t num_symbols = symtabsz / sizeof(Elf64_Sym);

    for (size_t i = 0; i < symtabsz; i++)
    {
        Elf64_Sym *sym = &symtab[i];
        char *sym_name = &strtab[sym->st_name];
        if (strcmp(symbol_name, sym_name) == 0)
        {
            if (sym->st_shndx == SHN_UNDEF)
            {
                printk("Symbol %s is undefined.\n", sym_name);
                return NULL;
            }
            void *addr = (void *)sym->st_value + offset;
            return addr;
        }
    }
    printk("Cannot find symbol %s in ELF file.\n", symbol_name);
    return NULL;
}

dlinit_t load_dynamic(Elf64_Phdr *phdrs, Elf64_Ehdr *ehdr, uint64_t offset)
{
    Elf64_Dyn *dyn_entry = NULL;
    for (size_t i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdrs[i].p_type == PT_DYNAMIC)
        {
            dyn_entry = (Elf64_Dyn *)(phdrs[i].p_vaddr);
            break;
        }
    }
    if (dyn_entry == NULL)
    {
        printk("Dynamic section not found.\n");
        return NULL;
    }
    uint64_t addr_dyn = ((uint64_t)dyn_entry) + offset;
    dyn_entry = (Elf64_Dyn *)addr_dyn;

    Elf64_Sym *symtab = NULL;
    char *strtab = NULL;
    Elf64_Rela *rel = NULL;
    Elf64_Rela *jmprel = NULL;
    size_t relsz = 0, jmprel_sz = 0;

    while (dyn_entry->d_tag != DT_NULL)
    {
        switch (dyn_entry->d_tag)
        {
        case DT_SYMTAB:
            uint64_t symtab_addr = dyn_entry->d_un.d_ptr + offset;
            symtab = (Elf64_Sym *)symtab_addr;
            break;
        case DT_STRTAB:
            strtab = (char *)dyn_entry->d_un.d_ptr + offset;
            break;
        case DT_RELA:
            uint64_t rel_addr = dyn_entry->d_un.d_ptr + offset;
            rel = (Elf64_Rela *)rel_addr;
            break;
        case DT_RELASZ:
            relsz = dyn_entry->d_un.d_val;
            break;
        case DT_JMPREL:
            uint64_t jmprel_addr = dyn_entry->d_un.d_ptr + offset;
            jmprel = (Elf64_Rela *)jmprel_addr;
            break;
        case DT_PLTRELSZ:
            jmprel_sz = dyn_entry->d_un.d_val;
            break;
        case DT_PLTGOT: /* 需要解析 PLT 表 */
            break;
        }
        dyn_entry++;
    }

    for (size_t i = 0; i < relsz / sizeof(Elf64_Rela); i++)
    {
        Elf64_Rela *r = &rel[i];
        uint64_t *reloc_addr = (uint64_t *)(r->r_offset + offset);
        uint32_t sym_idx = ELF64_R_SYM(r->r_info);
        uint32_t type = ELF64_R_TYPE(r->r_info);

        if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT)
        {
            *reloc_addr = (uint64_t)resolve_symbol(symtab, sym_idx) + offset;
        }
        else if (type == R_X86_64_RELATIVE)
        {
            *reloc_addr = (uint64_t)(offset + r->r_addend);
        }
        else if (type == R_X86_64_64)
        {
            *reloc_addr = (uint64_t)resolve_symbol(symtab, sym_idx) + r->r_addend + offset;
        }
    }
    if (!handle_relocations(jmprel, symtab, strtab, jmprel_sz, offset))
    {
        printk("Failed to handle relocations.\n");
        return NULL;
    }

    void *entry = find_symbol_address("dlmain", ehdr, offset);

    dlinit_t dlinit_func = (dlinit_t)entry;
    return dlinit_func;
}

void dlinker_load(module_t *module)
{
    if (module == NULL)
        return;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)module->data;
    if (!arch_check_elf(ehdr))
    {
        printk("No elf file.\n");
        return;
    }

    if (ehdr->e_type != ET_DYN)
    {
        printk("ELF file is not a dynamic library.\n");
        return;
    }

    uint64_t load_size = 0;

    Elf64_Phdr *phdrs = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    if (!mmap_phdr_segment(ehdr, phdrs, get_kernel_page_dir(), KERNEL_MODULES_SPACE_START + kernel_modules_load_offset, NULL, &load_size))
    {
        printk("Cannot mmap elf segment.\n");
        return;
    }

    dlinit_t dlinit = load_dynamic(phdrs, ehdr, KERNEL_MODULES_SPACE_START + kernel_modules_load_offset);
    if (dlinit == NULL)
    {
        printk("cannot load dynamic section.\n");
        return;
    }

    printk("Loaded module %s at %#018lx\n", module->module_name, KERNEL_MODULES_SPACE_START + kernel_modules_load_offset);

    int ret = dlinit();

    kernel_modules_load_offset += (load_size + DEFAULT_PAGE_SIZE - 1) & ~(DEFAULT_PAGE_SIZE - 1);
}

dlfunc_t *find_func(const char *name)
{
    for (size_t i = 0; i < dlfunc_count; i++)
    {
        dlfunc_t *entry = &__ksymtab_start[i];
        if (strcmp(entry->name, name) == 0)
        {
            return entry;
        }
        if (strcmp(name, "printf") == 0)
        {
            return &__printf;
        }
    }
    return NULL;
}

void find_kernel_symbol()
{
    dlfunc_count = __ksymtab_end - __ksymtab_start;
    for (size_t i = 0; i < dlfunc_count; i++)
    {
        dlfunc_t *entry = &__ksymtab_start[i];
    }
}

__attribute__((used, section(".limine_requests"))) static volatile struct limine_module_request modules_request =
    {
        .id = LIMINE_MODULE_REQUEST,
        .revision = 0,
};

void dlinker_init()
{
    find_kernel_symbol();

    for (uint64_t i = 0; i < modules_request.response->module_count; i++)
    {
        module_t module = {
            .is_use = false,
            .path = modules_request.response->modules[i]->path,
            .data = modules_request.response->modules[i]->address,
            .size = modules_request.response->modules[i]->size,
        };
        strcpy(module.module_name, module.path);

        dlinker_load(&module);
    }
}
