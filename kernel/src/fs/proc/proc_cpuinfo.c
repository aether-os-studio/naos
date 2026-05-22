#include <fs/proc/proc.h>
#include <libs/string_builder.h>
#include <task/ns.h>

static char *proc_gen_cpuinfo(size_t *content_len) {
    string_builder_t *builder = create_string_builder(512);
    if (!builder) {
        *content_len = 0;
        return NULL;
    }

    const char *arch = "unknown";
#if defined(__riscv__)
    arch = "riscv64";
#elif defined(__loongarch64__)
    arch = "loongarch64";
#elif defined(__aarch64__)
    arch = "aarch64";
#elif defined(__x86_64__)
    arch = "x86_64";
#endif

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
        string_builder_append(builder, "processor\t: %llu\n",
                              (unsigned long long)cpu);
        string_builder_append(builder, "model name\t: naos virtual cpu\n");
        string_builder_append(builder, "cpu MHz\t\t: 1000.000\n");
        string_builder_append(builder, "BogoMIPS\t: 1000.00\n");
        string_builder_append(builder, "isa\t\t: %s\n\n", arch);
    }

    *content_len = builder->size;
    char *data = builder->data;
    free(builder);
    return data;
}

size_t proc_cpuinfo_stat(proc_handle_t *handle) {
    (void)handle;
    size_t len = 0;
    char *content = proc_gen_cpuinfo(&len);
    free(content);
    return len;
}

size_t proc_cpuinfo_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    (void)handle;
    size_t len = 0;
    char *content = proc_gen_cpuinfo(&len);
    if (!content)
        return 0;
    if (offset >= len) {
        free(content);
        return 0;
    }

    size_t to_copy = MIN(size, len - offset);
    memcpy(addr, content + offset, to_copy);
    free(content);
    return to_copy;
}
