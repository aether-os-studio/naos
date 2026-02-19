#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define symbol_to_write(vaddr, tv, etv) ((vaddr < tv || vaddr > etv) ? 0 : 1)

struct kernel_symbol_entry_t {
    uint64_t vaddr;
    char type;
    char *symbol;
    int symbol_length;
};

struct kernel_symbol_entry_t *symbol_table;
uint64_t table_size = 0;
uint64_t entry_count = 0;
uint64_t text_vaddr, etext_vaddr;

int read_symbol(FILE *filp, struct kernel_symbol_entry_t *entry) {
    char str[512] = {0};
    if (fgets(str, sizeof(str), filp) != str)
        return -1;

    char symbol_name[512] = {0};
    if (sscanf(str, "%lx %c %511s", &entry->vaddr, &entry->type, symbol_name) !=
        3)
        return -1;

    size_t len = strlen(symbol_name);

    // 转义双引号
    char escaped[1024] = {0};
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (symbol_name[i] == '"')
            escaped[j++] = '\\';
        escaped[j++] = symbol_name[i];
    }

    entry->symbol = strdup(escaped);
    if (entry->symbol == NULL)
        return -1;

    entry->symbol_length = strlen(escaped) + 1;
    return 0;
}

void read_map(FILE *filp) {
    // 循环读入数据直到输入流结束
    while (!feof(filp)) {
        // 给符号表扩容
        if (entry_count >= table_size) {
            table_size += 100;
            // 由于使用了realloc，因此符号表原有的内容会被自动的copy过去
            symbol_table = (struct kernel_symbol_entry_t *)realloc(
                symbol_table,
                sizeof(struct kernel_symbol_entry_t) * table_size);
        }

        // 若成功读取符号表的内容，则将计数器+1
        if (read_symbol(filp, &symbol_table[entry_count]) == 0)
            ++entry_count;
    }

    // 查找符号表中的text和etext标签
    for (uint64_t i = 0; i < entry_count; ++i) {
        if (text_vaddr == 0ULL && strcmp(symbol_table[i].symbol, "_text") == 0)
            text_vaddr = symbol_table[i].vaddr;
        if (etext_vaddr == 0ULL &&
            strcmp(symbol_table[i].symbol, "_etext") == 0)
            etext_vaddr = symbol_table[i].vaddr;
        if (text_vaddr != 0ULL && etext_vaddr != 0ULL)
            break;
    }
}

void generate_result() {
    printf(".section .rodata\n\n");
    printf(".global kallsyms_address\n");
    printf(".align 8\n\n");

    printf("kallsyms_address:\n"); // 地址数组

    uint64_t last_vaddr = 0;
    uint64_t total_syms_to_write = 0; // 真正输出的符号的数量

    // 循环写入地址数组
    for (uint64_t i = 0; i < entry_count; ++i) {
        // 判断是否为text段的符号
        if (!symbol_to_write(symbol_table[i].vaddr, text_vaddr, etext_vaddr))
            continue;

        if (symbol_table[i].vaddr == last_vaddr)
            continue;

        // 输出符号地址
        printf("\t.quad\t%#lx\n", symbol_table[i].vaddr);
        ++total_syms_to_write;

        last_vaddr = symbol_table[i].vaddr;
    }

    putchar('\n');

    // 写入符号表的表项数量
    printf(".global kallsyms_num\n");
    printf(".align 8\n");
    printf("kallsyms_num:\n");
    printf("\t.quad\t%ld\n", total_syms_to_write);

    putchar('\n');

    // 循环写入符号名称的下标索引
    printf(".global kallsyms_names_index\n");
    printf(".align 8\n");
    printf("kallsyms_names_index:\n");
    uint64_t position = 0;
    last_vaddr = 0;
    for (uint64_t i = 0; i < entry_count; ++i) {
        // 判断是否为text段的符号
        if (!symbol_to_write(symbol_table[i].vaddr, text_vaddr, etext_vaddr))
            continue;

        if (symbol_table[i].vaddr == last_vaddr)
            continue;

        // 输出符号名称的偏移量
        printf("\t.quad\t%ld\n", position);
        position += symbol_table[i].symbol_length;
        last_vaddr = symbol_table[i].vaddr;
    }

    putchar('\n');

    // 输出符号名
    printf(".global kallsyms_names\n");
    printf(".align 8\n");
    printf("kallsyms_names:\n");

    last_vaddr = 0;
    for (uint64_t i = 0; i < entry_count; ++i) {
        // 判断是否为text段的符号
        if (!symbol_to_write(symbol_table[i].vaddr, text_vaddr, etext_vaddr))
            continue;

        if (symbol_table[i].vaddr == last_vaddr)
            continue;

        // 输出符号名称
        printf("\t.asciz\t\"%s\"\n", symbol_table[i].symbol);

        last_vaddr = symbol_table[i].vaddr;
    }

    putchar('\n');
}

int main(int argc, char **argv) {
    read_map(stdin);

    generate_result();
}
