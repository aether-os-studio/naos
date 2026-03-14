#include "dlinker.h"
#include <boot/boot.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/vfs.h>
#include <mm/mm.h>

uint64_t kernel_modules_load_offset = 0;

extern dlfunc_t __ksymtab_start[];
extern dlfunc_t __ksymtab_end[];
extern const uint64_t kallsyms_lookup_address[] __attribute__((weak));
extern const uint64_t kallsyms_lookup_num __attribute__((weak));
extern const uint64_t kallsyms_lookup_names_index[] __attribute__((weak));
extern const char kallsyms_lookup_names[] __attribute__((weak));

size_t dlfunc_count = 0;

static dlfunc_t __printf = {.name = "printf", .addr = (void *)printk};
static dlfunc_t resolved_func;
static module_symbol_t *loaded_module_symbols = NULL;
static size_t loaded_module_symbol_count = 0;
static size_t loaded_module_symbol_capacity = 0;

typedef struct {
    const char **exports;
    size_t export_count;
    size_t export_capacity;
    const char **imports;
    size_t import_count;
    size_t import_capacity;
    size_t *deps;
    size_t dep_count;
    size_t dep_capacity;
    bool scan_ok;
    bool has_missing_provider;
    bool has_ambiguous_provider;
} module_plan_t;

static void load_segment(Elf64_Phdr *phdr, void *elf, uint64_t offset) {
    size_t hi =
        PADDING_UP(phdr->p_vaddr + phdr->p_memsz, DEFAULT_PAGE_SIZE) + offset;
    size_t lo = PADDING_DOWN(phdr->p_vaddr, DEFAULT_PAGE_SIZE) + offset;

    uint64_t flags = PT_FLAG_R | PT_FLAG_W;

    map_page_range(get_current_page_dir(false), lo, (uint64_t)-1, hi - lo,
                   flags | ((phdr->p_flags & PF_X) ? PT_FLAG_X : 0));

    uint64_t p_vaddr = (uint64_t)phdr->p_vaddr + offset;
    uint64_t p_filesz = (uint64_t)phdr->p_filesz;
    uint64_t p_memsz = (uint64_t)phdr->p_memsz;

    memcpy((void *)p_vaddr, (const uint8_t *)elf + phdr->p_offset, p_filesz);

    if (p_memsz > p_filesz) {
        memset((void *)(p_vaddr + p_filesz), 0, p_memsz - p_filesz);
    }

    dma_sync_cpu_to_device((void *)p_vaddr, p_memsz);
}

static bool mmap_phdr_segment(Elf64_Ehdr *ehdr, Elf64_Phdr *phdrs,
                              uint64_t offset, uint64_t *load_size) {
    size_t i = 0;
    while (i < ehdr->e_phnum && phdrs[i].p_type != PT_LOAD) {
        i++;
    }

    if (i == ehdr->e_phnum) {
        return false;
    }

    uint64_t load_min = UINT64_MAX;
    uint64_t load_max = 0;

    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }

        load_segment(&phdrs[i], (void *)ehdr, offset);

        if (phdrs[i].p_vaddr + offset + phdrs[i].p_memsz > load_max) {
            load_max = PADDING_UP(phdrs[i].p_vaddr + offset + phdrs[i].p_memsz,
                                  DEFAULT_PAGE_SIZE);
        }
        if (phdrs[i].p_vaddr + offset < load_min) {
            load_min =
                PADDING_DOWN(phdrs[i].p_vaddr + offset, DEFAULT_PAGE_SIZE);
        }
    }

    if (load_size) {
        *load_size = load_max - load_min;
    }

    return true;
}

static bool kallsyms_lookup_available() {
    return (uintptr_t)&kallsyms_lookup_num != 0 &&
           (uintptr_t)kallsyms_lookup_address != 0 &&
           (uintptr_t)kallsyms_lookup_names_index != 0 &&
           (uintptr_t)kallsyms_lookup_names != 0;
}

static void *lookup_kernel_symbol_by_name(const char *name) {
    if (name == NULL || !kallsyms_lookup_available()) {
        return NULL;
    }

    const char *names = (const char *)kallsyms_lookup_names;
    for (size_t i = 0; i < kallsyms_lookup_num; i++) {
        const char *symbol_name = &names[kallsyms_lookup_names_index[i]];
        if (strcmp(symbol_name, name) == 0) {
            return (void *)kallsyms_lookup_address[i];
        }
    }

    return NULL;
}

static dlfunc_t *find_legacy_kernel_export(const char *name) {
    if (strcmp(name, "printf") == 0) {
        return &__printf;
    }

    for (size_t i = 0; i < dlfunc_count; i++) {
        dlfunc_t *entry = &__ksymtab_start[i];
        if (strcmp(entry->name, name) == 0) {
            return entry;
        }
    }

    return NULL;
}

static module_symbol_t *find_module_symbol(const char *name) {
    for (size_t i = 0; i < loaded_module_symbol_count; i++) {
        if (strcmp(loaded_module_symbols[i].name, name) == 0) {
            return &loaded_module_symbols[i];
        }
    }

    return NULL;
}

static bool ensure_module_symbol_capacity(size_t wanted) {
    if (wanted <= loaded_module_symbol_capacity) {
        return true;
    }

    size_t new_capacity =
        loaded_module_symbol_capacity ? loaded_module_symbol_capacity * 2 : 128;
    while (new_capacity < wanted) {
        new_capacity *= 2;
    }

    module_symbol_t *new_symbols =
        realloc(loaded_module_symbols, new_capacity * sizeof(*new_symbols));
    if (new_symbols == NULL) {
        return false;
    }

    loaded_module_symbols = new_symbols;
    loaded_module_symbol_capacity = new_capacity;
    return true;
}

static bool register_module_symbol(const char *module_name, const char *name,
                                   uint64_t addr) {
    if (name == NULL || *name == '\0') {
        return true;
    }

    if (!strcmp(name, "dlmain")) {
        return true;
    }

    if (find_module_symbol(name) != NULL) {
        printk("Skipping duplicate module symbol %s from %s\n", name,
               module_name);
        return true;
    }

    if (lookup_kernel_symbol_by_name(name) != NULL ||
        find_legacy_kernel_export(name) != NULL) {
        printk("Skipping module symbol %s from %s due to kernel conflict\n",
               name, module_name);
        return true;
    }

    if (!ensure_module_symbol_capacity(loaded_module_symbol_count + 1)) {
        printk("Cannot grow module symbol registry for %s\n", name);
        return false;
    }

    char *dup_name = strdup(name);
    if (dup_name == NULL) {
        printk("Cannot duplicate module symbol name %s\n", name);
        return false;
    }

    loaded_module_symbols[loaded_module_symbol_count].name = dup_name;
    loaded_module_symbols[loaded_module_symbol_count].addr = addr;
    loaded_module_symbol_count++;
    return true;
}

static bool get_module_symbol_table(Elf64_Ehdr *ehdr, Elf64_Sym **symtab,
                                    char **strtab, size_t *num_symbols) {
    if (ehdr == NULL || symtab == NULL || strtab == NULL ||
        num_symbols == NULL) {
        return false;
    }

    Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)ehdr + ehdr->e_shoff);
    Elf64_Shdr *candidate = NULL;

    for (size_t i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            candidate = &shdrs[i];
            break;
        }
    }

    if (candidate == NULL) {
        for (size_t i = 0; i < ehdr->e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_DYNSYM) {
                candidate = &shdrs[i];
                break;
            }
        }
    }

    if (candidate == NULL || candidate->sh_link >= ehdr->e_shnum) {
        return false;
    }

    *symtab = (Elf64_Sym *)((char *)ehdr + candidate->sh_offset);
    *strtab = (char *)ehdr + shdrs[candidate->sh_link].sh_offset;
    *num_symbols = candidate->sh_size / sizeof(Elf64_Sym);
    return true;
}

static bool ensure_string_list_capacity(const char ***items, size_t *capacity,
                                        size_t wanted) {
    if (wanted <= *capacity) {
        return true;
    }

    size_t new_capacity = *capacity ? *capacity * 2 : 16;
    while (new_capacity < wanted) {
        new_capacity *= 2;
    }

    const char **new_items =
        realloc((void *)*items, new_capacity * sizeof(**items));
    if (new_items == NULL) {
        return false;
    }

    *items = new_items;
    *capacity = new_capacity;
    return true;
}

static bool ensure_index_list_capacity(size_t **items, size_t *capacity,
                                       size_t wanted) {
    if (wanted <= *capacity) {
        return true;
    }

    size_t new_capacity = *capacity ? *capacity * 2 : 16;
    while (new_capacity < wanted) {
        new_capacity *= 2;
    }

    size_t *new_items =
        realloc(items ? *items : NULL, new_capacity * sizeof(*new_items));
    if (new_items == NULL) {
        return false;
    }

    *items = new_items;
    *capacity = new_capacity;
    return true;
}

static bool string_list_contains(const char *const *items, size_t count,
                                 const char *value) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(items[i], value) == 0) {
            return true;
        }
    }

    return false;
}

static bool append_unique_string(const char ***items, size_t *count,
                                 size_t *capacity, const char *value) {
    if (value == NULL || *value == '\0' ||
        string_list_contains(*items, *count, value)) {
        return true;
    }

    if (!ensure_string_list_capacity(items, capacity, *count + 1)) {
        return false;
    }

    (*items)[*count] = value;
    (*count)++;
    return true;
}

static bool index_list_contains(const size_t *items, size_t count,
                                size_t value) {
    for (size_t i = 0; i < count; i++) {
        if (items[i] == value) {
            return true;
        }
    }

    return false;
}

static bool append_unique_index(size_t **items, size_t *count, size_t *capacity,
                                size_t value) {
    if (index_list_contains(*items, *count, value)) {
        return true;
    }

    if (!ensure_index_list_capacity(items, capacity, *count + 1)) {
        return false;
    }

    (*items)[*count] = value;
    (*count)++;
    return true;
}

static bool kernel_can_resolve_symbol(const char *name) {
    return lookup_kernel_symbol_by_name(name) != NULL ||
           find_legacy_kernel_export(name) != NULL;
}

static bool module_symbol_is_visible(const Elf64_Sym *sym) {
    uint8_t visibility = ELF64_ST_VISIBILITY(sym->st_other);
    return visibility == STV_DEFAULT || visibility == STV_PROTECTED;
}

static bool module_symbol_is_exported(const Elf64_Sym *sym) {
    if (sym == NULL || sym->st_name == 0 || sym->st_shndx == SHN_UNDEF) {
        return false;
    }

    if (!module_symbol_is_visible(sym)) {
        return false;
    }

    uint8_t bind = ELF64_ST_BIND(sym->st_info);
    if (bind != STB_GLOBAL && bind != STB_WEAK) {
        return false;
    }

    uint8_t type = ELF64_ST_TYPE(sym->st_info);
    switch (type) {
    case STT_NOTYPE:
    case STT_OBJECT:
    case STT_FUNC:
    case STT_COMMON:
        return true;
    default:
        return false;
    }
}

static bool module_symbol_is_imported(const Elf64_Sym *sym) {
    if (sym == NULL || sym->st_name == 0 || sym->st_shndx != SHN_UNDEF) {
        return false;
    }

    if (!module_symbol_is_visible(sym)) {
        return false;
    }

    uint8_t bind = ELF64_ST_BIND(sym->st_info);
    return bind == STB_GLOBAL || bind == STB_WEAK;
}

static void register_module_symbols(module_t *module, Elf64_Ehdr *ehdr,
                                    uint64_t offset) {
    Elf64_Sym *symtab = NULL;
    char *strtab = NULL;
    size_t num_symbols = 0;

    if (!get_module_symbol_table(ehdr, &symtab, &strtab, &num_symbols)) {
        printk("Cannot find symbol table in module %s\n", module->module_name);
        return;
    }

    for (size_t i = 0; i < num_symbols; i++) {
        Elf64_Sym *sym = &symtab[i];
        if (!module_symbol_is_exported(sym)) {
            continue;
        }

        uint64_t addr =
            sym->st_shndx == SHN_ABS ? sym->st_value : offset + sym->st_value;
        register_module_symbol(module->module_name, &strtab[sym->st_name],
                               addr);
    }
}

static void free_module_plan(module_plan_t *plan) {
    if (plan == NULL) {
        return;
    }

    free((void *)plan->exports);
    free((void *)plan->imports);
    free(plan->deps);
    memset(plan, 0, sizeof(*plan));
}

static bool scan_module_symbols(module_t *module, module_plan_t *plan) {
    if (module == NULL || plan == NULL) {
        return false;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)module->data;
    if (!arch_check_elf(ehdr)) {
        printk("Module %s is not a valid ELF file.\n", module->module_name);
        return false;
    }

    if (ehdr->e_type != ET_DYN) {
        printk("Module %s is not a dynamic ELF file.\n", module->module_name);
        return false;
    }

    Elf64_Sym *symtab = NULL;
    char *strtab = NULL;
    size_t num_symbols = 0;

    if (!get_module_symbol_table(ehdr, &symtab, &strtab, &num_symbols)) {
        printk("Cannot find symbol table in module %s\n", module->module_name);
        return false;
    }

    for (size_t i = 0; i < num_symbols; i++) {
        Elf64_Sym *sym = &symtab[i];
        const char *sym_name = &strtab[sym->st_name];

        if (module_symbol_is_exported(sym)) {
            if (!strcmp(sym_name, "dlmain")) {
                continue;
            }

            if (!append_unique_string(&plan->exports, &plan->export_count,
                                      &plan->export_capacity, sym_name)) {
                return false;
            }
        }

        if (module_symbol_is_imported(sym)) {
            if (!append_unique_string(&plan->imports, &plan->import_count,
                                      &plan->import_capacity, sym_name)) {
                return false;
            }
        }
    }

    plan->scan_ok = true;
    return true;
}

static size_t count_symbol_providers(module_plan_t *plans, size_t module_count,
                                     const char *symbol_name,
                                     size_t requester_index,
                                     size_t *provider_index) {
    size_t matches = 0;

    for (size_t i = 0; i < module_count; i++) {
        if (i == requester_index || !plans[i].scan_ok) {
            continue;
        }

        if (!string_list_contains(plans[i].exports, plans[i].export_count,
                                  symbol_name)) {
            continue;
        }

        if (provider_index != NULL) {
            *provider_index = i;
        }
        matches++;
    }

    return matches;
}

static void resolve_module_dependencies(module_t *modules, module_plan_t *plans,
                                        size_t module_count) {
    for (size_t i = 0; i < module_count; i++) {
        if (!plans[i].scan_ok) {
            continue;
        }

        for (size_t j = 0; j < plans[i].import_count; j++) {
            const char *symbol_name = plans[i].imports[j];

            if (kernel_can_resolve_symbol(symbol_name)) {
                continue;
            }

            size_t provider_index = 0;
            size_t provider_count = count_symbol_providers(
                plans, module_count, symbol_name, i, &provider_index);

            if (provider_count == 1) {
                if (!append_unique_index(&plans[i].deps, &plans[i].dep_count,
                                         &plans[i].dep_capacity,
                                         provider_index)) {
                    printk("Cannot record dependency %s -> %s\n",
                           modules[i].module_name,
                           modules[provider_index].module_name);
                    plans[i].has_missing_provider = true;
                }
                continue;
            }

            if (provider_count == 0) {
                printk("Module %s misses provider for symbol %s\n",
                       modules[i].module_name, symbol_name);
                plans[i].has_missing_provider = true;
                continue;
            }

            printk("Module %s has ambiguous providers for symbol %s\n",
                   modules[i].module_name, symbol_name);
            plans[i].has_ambiguous_provider = true;
        }
    }
}

static bool module_dependencies_ready(const module_plan_t *plan,
                                      const bool *loaded_flags) {
    if (plan == NULL || loaded_flags == NULL) {
        return false;
    }

    if (!plan->scan_ok || plan->has_missing_provider ||
        plan->has_ambiguous_provider) {
        return false;
    }

    for (size_t i = 0; i < plan->dep_count; i++) {
        if (!loaded_flags[plan->deps[i]]) {
            return false;
        }
    }

    return true;
}

static void *resolve_symbol(Elf64_Sym *symtab, char *strtab, uint32_t sym_idx) {
    Elf64_Sym *sym = &symtab[sym_idx];

    if (sym->st_shndx == SHN_UNDEF) {
        char *sym_name = &strtab[sym->st_name];
        dlfunc_t *func = find_func(sym_name);
        if (func != NULL) {
            return func->addr;
        }
        printk("Cannot resolve symbol: %s\n", sym_name);
        return NULL;
    }

    return (void *)sym->st_value;
}

static bool handle_relocations(Elf64_Rela *rela_start, Elf64_Sym *symtab,
                               char *strtab, size_t jmprel_sz,
                               uint64_t offset) {
    if (!rela_start || jmprel_sz == 0) {
        return true;
    }

    size_t rela_count = jmprel_sz / sizeof(Elf64_Rela);

    for (size_t i = 0; i < rela_count; i++) {
        Elf64_Rela *rela = &rela_start[i];
        uint64_t *target_addr = (uint64_t *)(rela->r_offset + offset);
        uint32_t sym_idx = ELF64_R_SYM(rela->r_info);
        uint32_t type = ELF64_R_TYPE(rela->r_info);

        Elf64_Sym *sym = &symtab[sym_idx];
        char *sym_name = &strtab[sym->st_name];

#if defined(__x86_64__)
        if (type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT) {
            void *sym_addr = resolve_symbol(symtab, strtab, sym_idx);
            if (sym_addr == NULL) {
                printk("Failed relocating %s at %p\n", sym_name, target_addr);
                return false;
            }

            if (sym->st_shndx == SHN_UNDEF) {
                *target_addr = (uint64_t)sym_addr;
            } else {
                *target_addr = (uint64_t)sym_addr + offset;
            }
        } else if (type == R_X86_64_RELATIVE) {
            *target_addr = offset + rela->r_addend;
        } else if (type == R_X86_64_64) {
            void *sym_addr = resolve_symbol(symtab, strtab, sym_idx);
            if (sym_addr == NULL) {
                printk("Failed relocating %s at %p\n", sym_name, target_addr);
                return false;
            }

            if (sym->st_shndx == SHN_UNDEF) {
                *target_addr = (uint64_t)sym_addr + rela->r_addend;
            } else {
                *target_addr = (uint64_t)sym_addr + offset + rela->r_addend;
            }
        }
#elif defined(__aarch64__)
        if (type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_GLOB_DAT) {
            void *sym_addr = resolve_symbol(symtab, strtab, sym_idx);
            if (sym_addr == NULL) {
                printk("Failed relocating %s at %p\n", sym_name, target_addr);
                return false;
            }

            if (sym->st_shndx == SHN_UNDEF) {
                *target_addr = (uint64_t)sym_addr;
            } else {
                *target_addr = (uint64_t)sym_addr + offset;
            }
        } else if (type == R_AARCH64_RELATIVE) {
            *target_addr = offset + rela->r_addend;
        } else if (type == R_AARCH64_ABS64) {
            void *sym_addr = resolve_symbol(symtab, strtab, sym_idx);
            if (sym_addr == NULL) {
                printk("Failed relocating %s at %p\n", sym_name, target_addr);
                return false;
            }

            if (sym->st_shndx == SHN_UNDEF) {
                *target_addr = (uint64_t)sym_addr + rela->r_addend;
            } else {
                *target_addr = (uint64_t)sym_addr + offset + rela->r_addend;
            }
        }
#elif defined(__riscv) && (__riscv_xlen == 64)
        if (type == R_RISCV_JUMP_SLOT) {
            void *sym_addr = resolve_symbol(symtab, strtab, sym_idx);
            if (sym_addr == NULL) {
                printk("Failed relocating %s at %p\n", sym_name, target_addr);
                return false;
            }

            if (sym->st_shndx == SHN_UNDEF) {
                *target_addr = (uint64_t)sym_addr;
            } else {
                *target_addr = (uint64_t)sym_addr + offset;
            }
        } else if (type == R_RISCV_RELATIVE) {
            *target_addr = offset + rela->r_addend;
        } else if (type == R_RISCV_64) {
            void *sym_addr = resolve_symbol(symtab, strtab, sym_idx);
            if (sym_addr == NULL) {
                printk("Failed relocating %s at %p\n", sym_name, target_addr);
                return false;
            }

            if (sym->st_shndx == SHN_UNDEF) {
                *target_addr = (uint64_t)sym_addr + rela->r_addend;
            } else {
                *target_addr = (uint64_t)sym_addr + offset + rela->r_addend;
            }
        }
#elif defined(__loongarch64) || defined(__loongarch64__)
        if (type == R_LARCH_JUMP_SLOT) {
            void *sym_addr = resolve_symbol(symtab, strtab, sym_idx);
            if (sym_addr == NULL) {
                printk("Failed relocating %s at %p\n", sym_name, target_addr);
                return false;
            }

            if (sym->st_shndx == SHN_UNDEF) {
                *target_addr = (uint64_t)sym_addr;
            } else {
                *target_addr = (uint64_t)sym_addr + offset;
            }
        } else if (type == R_LARCH_RELATIVE) {
            *target_addr = offset + rela->r_addend;
        } else if (type == R_LARCH_64) {
            void *sym_addr = resolve_symbol(symtab, strtab, sym_idx);
            if (sym_addr == NULL) {
                printk("Failed relocating %s at %p\n", sym_name, target_addr);
                return false;
            }

            if (sym->st_shndx == SHN_UNDEF) {
                *target_addr = (uint64_t)sym_addr + rela->r_addend;
            } else {
                *target_addr = (uint64_t)sym_addr + offset + rela->r_addend;
            }
        } else if (type != R_LARCH_NONE) {
            printk("Unsupported LoongArch relocation type %u for %s at %p\n",
                   type, sym_name, target_addr);
            return false;
        }
#endif
    }

    return true;
}

static void *find_symbol_address(const char *symbol_name, Elf64_Ehdr *ehdr,
                                 uint64_t offset) {
    if (symbol_name == NULL || ehdr == NULL) {
        return NULL;
    }

    Elf64_Sym *symtab = NULL;
    char *strtab = NULL;
    size_t num_symbols = 0;

    if (!get_module_symbol_table(ehdr, &symtab, &strtab, &num_symbols)) {
        printk("Cannot find symbol table in ELF file.\n");
        return NULL;
    }

    for (size_t i = 0; i < num_symbols; i++) {
        Elf64_Sym *sym = &symtab[i];
        char *sym_name = &strtab[sym->st_name];

        if (strcmp(symbol_name, sym_name) != 0) {
            continue;
        }

        if (sym->st_shndx == SHN_UNDEF) {
            printk("Symbol %s is undefined.\n", sym_name);
            return NULL;
        }

        return (void *)(offset + sym->st_value);
    }

    printk("Cannot find symbol %s in ELF file.\n", symbol_name);
    return NULL;
}

static dlinit_t load_dynamic(Elf64_Phdr *phdrs, Elf64_Ehdr *ehdr,
                             uint64_t offset) {
    Elf64_Dyn *dyn_entry = NULL;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_entry = (Elf64_Dyn *)(phdrs[i].p_vaddr + offset);
            break;
        }
    }
    if (dyn_entry == NULL) {
        printk("Dynamic section not found.\n");
        return NULL;
    }

    Elf64_Sym *symtab = NULL;
    char *strtab = NULL;
    Elf64_Rela *rel = NULL;
    Elf64_Rela *jmprel = NULL;
    size_t relsz = 0;
    size_t jmprel_sz = 0;

    while (dyn_entry->d_tag != DT_NULL) {
        switch (dyn_entry->d_tag) {
        case DT_SYMTAB:
            symtab = (Elf64_Sym *)(dyn_entry->d_un.d_ptr + offset);
            break;
        case DT_STRTAB:
            strtab = (char *)(dyn_entry->d_un.d_ptr + offset);
            break;
        case DT_RELA:
            rel = (Elf64_Rela *)(dyn_entry->d_un.d_ptr + offset);
            break;
        case DT_RELASZ:
            relsz = dyn_entry->d_un.d_val;
            break;
        case DT_JMPREL:
            jmprel = (Elf64_Rela *)(dyn_entry->d_un.d_ptr + offset);
            break;
        case DT_PLTRELSZ:
            jmprel_sz = dyn_entry->d_un.d_val;
            break;
        }
        dyn_entry++;
    }

    if (!handle_relocations(rel, symtab, strtab, relsz, offset)) {
        printk("Failed to handle RELA relocations.\n");
        return NULL;
    }

    if (!handle_relocations(jmprel, symtab, strtab, jmprel_sz, offset)) {
        printk("Failed to handle PLT relocations.\n");
        return NULL;
    }

    void *entry = find_symbol_address("dlmain", ehdr, offset);
    if (entry == NULL) {
        printk("Cannot find dlmain symbol.\n");
        return NULL;
    }

    return (dlinit_t)entry;
}

bool dlinker_load(module_t *module) {
    if (module == NULL || module->is_use) {
        return module != NULL;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)module->data;
    if (!arch_check_elf(ehdr)) {
        printk("Module %s is not a valid ELF file.\n", module->module_name);
        return false;
    }

    if (ehdr->e_type != ET_DYN) {
        printk("Module %s is not a dynamic ELF file.\n", module->module_name);
        return false;
    }

    Elf64_Phdr *phdrs = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);

    if (!module->mapped) {
        uint64_t load_base =
            KERNEL_MODULES_SPACE_START + kernel_modules_load_offset;

        if (!mmap_phdr_segment(ehdr, phdrs, load_base, &module->load_size)) {
            printk("Cannot map module %s\n", module->module_name);
            return false;
        }

        module->load_base = load_base;
        module->mapped = true;
        kernel_modules_load_offset +=
            PADDING_UP(module->load_size, DEFAULT_PAGE_SIZE);
    }

    dlinit_t dlinit = load_dynamic(phdrs, ehdr, module->load_base);
    if (dlinit == NULL) {
        return false;
    }

    register_module_symbols(module, ehdr, module->load_base);

    printk("Loaded module %s at %#018lx\n", module->module_name,
           module->load_base);

    dlinit();
    module->is_use = true;
    return true;
}

dlfunc_t *find_func(const char *name) {
    if (name == NULL) {
        return NULL;
    }

    module_symbol_t *module_symbol = find_module_symbol(name);
    if (module_symbol != NULL) {
        resolved_func.name = module_symbol->name;
        resolved_func.addr = (void *)module_symbol->addr;
        return &resolved_func;
    }

    void *kernel_symbol = lookup_kernel_symbol_by_name(name);
    if (kernel_symbol != NULL) {
        resolved_func.name = (char *)name;
        resolved_func.addr = kernel_symbol;
        return &resolved_func;
    }

    return find_legacy_kernel_export(name);
}

void find_kernel_symbol() { dlfunc_count = __ksymtab_end - __ksymtab_start; }

void dlinker_init() {
    find_kernel_symbol();

    vfs_node_t modules_root = vfs_open("/lib/modules", 0);
    if (!modules_root) {
        return;
    }

    module_t *modules = NULL;
    size_t module_count = 0;
    size_t module_capacity = 0;

    vfs_node_t node, tmp;
    llist_for_each(node, tmp, &modules_root->childs, node_for_childs) {
        if (module_count >= module_capacity) {
            size_t new_capacity = module_capacity ? module_capacity * 2 : 16;
            module_t *new_modules =
                realloc(modules, new_capacity * sizeof(*new_modules));
            if (new_modules == NULL) {
                printk("Cannot grow module list\n");
                break;
            }
            modules = new_modules;
            module_capacity = new_capacity;
        }

        module_t *module = &modules[module_count];
        memset(module, 0, sizeof(*module));
        strncpy(module->module_name, node->name, sizeof(module->module_name));
        module->path = node->name;
        module->size = node->size;
        module->data = alloc_frames_bytes(module->size);
        if (module->data == NULL) {
            printk("Cannot allocate backing storage for module %s\n",
                   module->module_name);
            continue;
        }

        vfs_read(node, module->data, 0, module->size);
        module_count++;
    }

    module_plan_t *plans = calloc(module_count, sizeof(*plans));
    bool *loaded_flags = calloc(module_count, sizeof(*loaded_flags));
    if (plans == NULL || loaded_flags == NULL) {
        printk("Cannot allocate module dependency planner\n");
        free(plans);
        free(loaded_flags);
        plans = NULL;
        loaded_flags = NULL;
    }

    if (plans != NULL && loaded_flags != NULL) {
        for (size_t i = 0; i < module_count; i++) {
            if (!scan_module_symbols(&modules[i], &plans[i])) {
                printk("Skipping dependency scan for module %s\n",
                       modules[i].module_name);
            }
        }

        resolve_module_dependencies(modules, plans, module_count);

        size_t loaded_count = 0;
        bool progress = true;

        while (loaded_count < module_count && progress) {
            progress = false;

            for (size_t i = 0; i < module_count; i++) {
                if (loaded_flags[i] ||
                    !module_dependencies_ready(&plans[i], loaded_flags)) {
                    continue;
                }

                if (dlinker_load(&modules[i])) {
                    loaded_flags[i] = true;
                    loaded_count++;
                    progress = true;
                } else {
                    printk("Module %s failed after dependency resolution\n",
                           modules[i].module_name);
                    loaded_flags[i] = true;
                }
            }
        }

        for (size_t i = 0; i < module_count; i++) {
            if (modules[i].is_use) {
                continue;
            }

            if (!plans[i].scan_ok) {
                printk("Module %s was not loaded: scan failed\n",
                       modules[i].module_name);
                continue;
            }

            if (plans[i].has_missing_provider) {
                printk(
                    "Module %s was not loaded: missing dependency provider\n",
                    modules[i].module_name);
                continue;
            }

            if (plans[i].has_ambiguous_provider) {
                printk(
                    "Module %s was not loaded: ambiguous dependency provider\n",
                    modules[i].module_name);
                continue;
            }

            printk(
                "Module %s was not loaded: dependency cycle or init failure\n",
                modules[i].module_name);
        }
    }

    for (size_t i = 0; i < module_count; i++) {
        if (plans != NULL) {
            free_module_plan(&plans[i]);
        }

        if (modules[i].data != NULL) {
            free_frames_bytes(modules[i].data, modules[i].size);
        }
    }

    free(plans);
    free(loaded_flags);
    free(modules);
}
