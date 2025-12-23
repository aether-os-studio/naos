#include <fs/vfs/proc/proc.h>
#include <task/task.h>
#include <libs/string_builder.h>

char *proc_gen_status_file(task_t *task, size_t *content_len) {
    string_builder_t *builder = create_string_builder(1024);
    string_builder_append(builder, "NStgid: N/A\n"
                                   "NSpid: N/A\n"
                                   "NSpgid: N/A\n"
                                   "NSsid: N/A\n"
                                   "VmPeak: N/A kB\n"
                                   "VmSize: N/A kB\n"
                                   "VmLck: 0 kB\n"
                                   "VmPin: 0 kB\n"
                                   "VmHWM: N/A kB\n"
                                   "VmRSS: N/A kB\n"
                                   "RssAnon: N/A kB\n"
                                   "RssFile: N/A kB\n"
                                   "RssShmem: N/A kB\n"
                                   "VmData: N/A kB\n"
                                   "VmStk: N/A kB\n"
                                   "VmExe: N/A kB\n"
                                   "VmLib: N/A kB\n"
                                   "VmPTE: N/A kB\n"
                                   "VmSwap: 0 kB\n"
                                   "HugetlbPages: N/A kB\n"
                                   "SigPnd: 0000000000000000\n"
                                   "ShdPnd: 0000000000000000\n"
                                   "SigBlk: 0000000000000000\n"
                                   "SigIgn: 0000000000000000\n"
                                   "SigCgt: 0000000000000000\n"
                                   "CapInh: 0000000000000000\n"
                                   "CapPrm: 0000000000000000\n"
                                   "CapEff: 0000000000000000\n"
                                   "CapBnd: 0000000000000000\n"
                                   "CapAmb: 0000000000000000\n");
    char *data = builder->data;
    *content_len = builder->size;
    free(builder);
    return data;
}

size_t proc_pstatus_stat(proc_handle_t *handle) {
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }
    size_t content_len = 0;
    char *content = proc_gen_status_file(task, &content_len);
    free(content);
    return content_len;
}

size_t proc_pstatus_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }
    size_t content_len = 0;
    char *content = proc_gen_status_file(task, &content_len);
    if (offset >= content_len) {
        free(content);
        return 0;
    }
    content_len = MIN(content_len, offset + size);
    size_t to_copy = MIN(content_len, size);
    memcpy(addr, content + offset, to_copy);
    free(content);
    ((char *)addr)[to_copy] = '\0';
    return to_copy;
}
