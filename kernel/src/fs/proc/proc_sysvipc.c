#include <fs/proc/proc.h>
#include <libs/string_builder.h>
#include <mm/shm.h>

static char *proc_gen_sysvipc_shm(size_t *content_len) {
    string_builder_t *builder = create_string_builder(512);
    if (!builder) {
        *content_len = 0;
        return NULL;
    }

    string_builder_append(builder, "       key      shmid perms                "
                                   "  size   cpid   lpid nattch\n");

    size_t count = shm_snapshot(NULL, 0);
    shm_snapshot_entry_t *entries = NULL;
    if (count > 0) {
        entries = calloc(count, sizeof(*entries));
        if (!entries) {
            free(builder->data);
            free(builder);
            *content_len = 0;
            return NULL;
        }
        count = shm_snapshot(entries, count);
    }

    for (size_t i = 0; i < count; i++) {
        string_builder_append(
            builder, "%10d %10d %5o %21llu %6d %6d %6d\n", entries[i].key,
            entries[i].shmid, entries[i].mode & 07777,
            (unsigned long long)entries[i].size, entries[i].cpid,
            entries[i].lpid, entries[i].nattch);
    }
    free(entries);

    *content_len = builder->size;
    char *data = builder->data;
    free(builder);
    return data;
}

size_t proc_sysvipc_shm_stat(proc_handle_t *handle) {
    (void)handle;
    size_t len = 0;
    char *content = proc_gen_sysvipc_shm(&len);
    free(content);
    return len;
}

size_t proc_sysvipc_shm_read(proc_handle_t *handle, void *addr, size_t offset,
                             size_t size) {
    (void)handle;
    size_t len = 0;
    char *content = proc_gen_sysvipc_shm(&len);
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
