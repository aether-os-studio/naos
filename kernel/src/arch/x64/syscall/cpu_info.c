#include <arch/x64/syscall/cpu_info.h>
#include <stdarg.h>
#include <mm/mm.h>

extern uint64_t cpu_count;

// 动态增长的缓冲区实现
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} dynamic_buffer_t;

static dynamic_buffer_t *create_dynamic_buffer(size_t initial_capacity) {
    dynamic_buffer_t *buf = malloc(sizeof(dynamic_buffer_t));
    if (!buf)
        return NULL;

    buf->data = malloc(initial_capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->size = 0;
    buf->capacity = initial_capacity;
    buf->data[0] = '\0';

    return buf;
}

static bool dynamic_buffer_append(dynamic_buffer_t *buf, const char *format,
                                  ...) {
    va_list args;
    int needed;

    // 计算需要的空间
    va_start(args, format);
    needed = vsnprintf(NULL, UINT64_MAX, format, args);
    va_end(args);

    if (needed < 0)
        return false;

    // 检查是否需要扩展缓冲区
    size_t required = buf->size + needed + 1;
    if (required > buf->capacity) {
        size_t new_capacity = buf->capacity;
        while (new_capacity < required) {
            new_capacity *= 2;
        }

        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data)
            return false;

        buf->data = new_data;
        buf->capacity = new_capacity;
    }

    // 添加新内容
    va_start(args, format);
    int written = vsnprintf(buf->data + buf->size, buf->capacity - buf->size,
                            format, args);
    va_end(args);

    if (written > 0) {
        buf->size += written;
    }

    return written >= 0;
}

static bool add_cpu_info_to_buffer(dynamic_buffer_t *buf,
                                   struct cpu_info *info) {
    bool success = true;

    success &= dynamic_buffer_append(buf, "processor\t: %d\n", info->processor);
    success &= dynamic_buffer_append(buf, "vendor_id\t: %s\n", info->vendor_id);
    success &=
        dynamic_buffer_append(buf, "cpu family\t: %d\n", info->cpu_family);
    success &= dynamic_buffer_append(buf, "model\t\t: %d\n", info->model);
    success &=
        dynamic_buffer_append(buf, "model name\t: %s\n", info->model_name);
    success &= dynamic_buffer_append(buf, "stepping\t: %d\n", info->stepping);

    if (info->microcode > 0) {
        success &=
            dynamic_buffer_append(buf, "microcode\t: 0x%x\n", info->microcode);
    }

    success &=
        dynamic_buffer_append(buf, "cpu MHz\t\t: %d.%03d\n",
                              info->cpu_mhz / 1000, info->cpu_mhz % 1000);
    success &=
        dynamic_buffer_append(buf, "cache size\t: %d KB\n", info->cache_size);

    success &=
        dynamic_buffer_append(buf, "physical id\t: %d\n", info->physical_id);
    success &= dynamic_buffer_append(buf, "siblings\t: %d\n", info->siblings);
    success &= dynamic_buffer_append(buf, "core id\t\t: %d\n", info->core_id);
    success &= dynamic_buffer_append(buf, "cpu cores\t: %d\n", info->cpu_cores);
    success &= dynamic_buffer_append(buf, "apicid\t\t: %d\n", info->apicid);
    success &= dynamic_buffer_append(buf, "initial apicid\t: %d\n",
                                     info->initial_apicid);

    success &=
        dynamic_buffer_append(buf, "fpu\t\t: %s\n", info->fpu ? "yes" : "no");
    success &= dynamic_buffer_append(buf, "fpu_exception\t: %s\n",
                                     info->fpu_exception ? "yes" : "no");
    success &=
        dynamic_buffer_append(buf, "cpuid level\t: %d\n", info->cpuid_level);
    success &=
        dynamic_buffer_append(buf, "wp\t\t: %s\n", info->wp ? "yes" : "no");

    success &= dynamic_buffer_append(buf, "flags\t\t: %s\n", info->flags);

    if (info->bugs[0]) {
        success &= dynamic_buffer_append(buf, "bugs\t\t: %s\n", info->bugs);
    }

    success &=
        dynamic_buffer_append(buf, "bogomips\t: %d.%02d\n",
                              info->bogomips / 100, info->bogomips % 100);
    success &=
        dynamic_buffer_append(buf, "clflush size\t: %d\n", info->clflush_size);
    success &= dynamic_buffer_append(buf, "cache_alignment\t: %d\n",
                                     info->cache_alignment);
    success &= dynamic_buffer_append(buf, "address sizes\t: %s\n",
                                     info->address_sizes);

    if (info->power_management[0]) {
        success &= dynamic_buffer_append(buf, "power management: %s\n",
                                         info->power_management);
    }

    success &= dynamic_buffer_append(buf, "\n");

    return success;
}

char *generate_cpuinfo_buffer_dynamic(void) {
    dynamic_buffer_t *buf = create_dynamic_buffer(4096);
    if (!buf)
        return NULL;

    for (int cpu = 0; cpu < cpu_count; cpu++) {
        struct cpu_info info;

        detect_cpu_info(&info, cpu);

        // 添加CPU信息
        if (!add_cpu_info_to_buffer(buf, &info)) {
            free(buf->data);
            free(buf);
            return NULL;
        }
    }

    char *result = buf->data;
    free(buf); // 只释放结构体，不释放data
    return result;
}
