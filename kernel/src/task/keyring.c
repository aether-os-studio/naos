#include <task/keyring.h>

#define TASK_KEY_TYPE_MAX 32
#define TASK_KEY_DESC_MAX 256
#define TASK_KEY_NAME_MAX 256
#define TASK_KEY_PAYLOAD_MAX (64 * 1024)
#define TASK_KEYRING_ITEM_INIT_CAP 4

typedef enum task_key_object_type {
    TASK_KEY_OBJECT_KEY = 1,
    TASK_KEY_OBJECT_KEYRING = 2,
} task_key_object_type_t;

typedef struct task_key_object {
    task_key_object_type_t type;
    key_serial_t serial;
    int ref_count;
    int64_t uid;
    int64_t gid;
    uint32_t perm;
    uint64_t expiry_ns;
    char *description;
} task_key_object_t;

typedef struct task_key {
    task_key_object_t object;
    char *key_type;
    void *payload;
    size_t payload_len;
} task_key_t;

struct task_keyring {
    task_key_object_t object;
    task_key_object_t **items;
    size_t item_count;
    size_t item_capacity;
    bool persistent_user;
    uint64_t owner_uid;
};

static spinlock_t task_keyring_lock = SPIN_INIT;
static hashmap_t task_key_serial_map = HASHMAP_INIT;
static hashmap_t task_user_keyring_map = HASHMAP_INIT;
static key_serial_t task_next_key_serial = 1;

static inline uint64_t task_key_serial_hash(key_serial_t serial) {
    return (uint64_t)(uint32_t)serial;
}

static inline bool task_key_is_expired(const task_key_object_t *object,
                                       uint64_t now_ns) {
    return object && object->expiry_ns != 0 && now_ns >= object->expiry_ns;
}

static key_serial_t task_key_alloc_serial_locked(void) {
    key_serial_t serial = task_next_key_serial++;
    if (serial <= 0) {
        task_next_key_serial = 1;
        serial = task_next_key_serial++;
    }
    return serial;
}

static char *task_key_copy_string(const char *src) {
    return src ? strdup(src) : strdup("");
}

static task_keyring_t *task_keyring_alloc(const char *description, int64_t uid,
                                          int64_t gid, bool persistent_user) {
    task_keyring_t *ring = calloc(1, sizeof(*ring));
    if (!ring)
        return NULL;

    ring->object.type = TASK_KEY_OBJECT_KEYRING;
    ring->object.ref_count = persistent_user ? 1 : 0;
    ring->object.uid = uid;
    ring->object.gid = gid;
    ring->object.perm = KEY_POS_ALL | KEY_USR_ALL;
    ring->object.description = task_key_copy_string(description);
    ring->persistent_user = persistent_user;
    ring->owner_uid = uid >= 0 ? (uint64_t)uid : 0;

    if (!ring->object.description) {
        free(ring);
        return NULL;
    }

    return ring;
}

static task_key_t *task_key_alloc(const char *type, const char *description,
                                  int64_t uid, int64_t gid, const void *payload,
                                  size_t payload_len) {
    task_key_t *key = calloc(1, sizeof(*key));
    if (!key)
        return NULL;

    key->object.type = TASK_KEY_OBJECT_KEY;
    key->object.ref_count = 0;
    key->object.uid = uid;
    key->object.gid = gid;
    key->object.perm = KEY_POS_ALL | KEY_USR_ALL;
    key->object.description = task_key_copy_string(description);
    key->key_type = task_key_copy_string(type);
    key->payload_len = payload_len;

    if ((payload_len > 0 && !payload) || !key->object.description ||
        !key->key_type) {
        free(key->object.description);
        free(key->key_type);
        free(key);
        return NULL;
    }

    if (payload_len > 0) {
        key->payload = malloc(payload_len);
        if (!key->payload) {
            free(key->object.description);
            free(key->key_type);
            free(key);
            return NULL;
        }

        memcpy(key->payload, payload, payload_len);
    }

    return key;
}

static int task_keyring_insert_object_locked(task_key_object_t *object) {
    if (!object)
        return -EINVAL;

    if (object->serial <= 0)
        object->serial = task_key_alloc_serial_locked();

    return hashmap_put(&task_key_serial_map,
                       task_key_serial_hash(object->serial), object);
}

static int task_keyring_ensure_capacity_locked(task_keyring_t *ring,
                                               size_t needed) {
    if (!ring)
        return -EINVAL;

    if (needed <= ring->item_capacity)
        return 0;

    size_t new_capacity =
        ring->item_capacity ? ring->item_capacity : TASK_KEYRING_ITEM_INIT_CAP;
    while (new_capacity < needed)
        new_capacity <<= 1;

    task_key_object_t **new_items =
        realloc(ring->items, new_capacity * sizeof(*new_items));
    if (!new_items)
        return -ENOMEM;

    ring->items = new_items;
    ring->item_capacity = new_capacity;
    return 0;
}

static void task_key_object_get_locked(task_key_object_t *object) {
    if (object)
        object->ref_count++;
}

static void task_key_object_destroy_locked(task_key_object_t *object);

static void task_key_object_put_locked(task_key_object_t *object) {
    if (!object)
        return;

    if (--object->ref_count > 0)
        return;

    task_key_object_destroy_locked(object);
}

static void task_key_object_destroy_locked(task_key_object_t *object) {
    if (!object)
        return;

    hashmap_remove(&task_key_serial_map, task_key_serial_hash(object->serial));

    if (object->type == TASK_KEY_OBJECT_KEYRING) {
        task_keyring_t *ring = (task_keyring_t *)object;

        if (ring->persistent_user)
            hashmap_remove(&task_user_keyring_map, ring->owner_uid);

        for (size_t i = 0; i < ring->item_count; i++)
            task_key_object_put_locked(ring->items[i]);

        free(ring->items);
        free(ring->object.description);
        free(ring);
        return;
    }

    task_key_t *key = (task_key_t *)object;
    free(key->payload);
    free(key->key_type);
    free(key->object.description);
    free(key);
}

static task_key_object_t *task_key_lookup_locked(key_serial_t serial) {
    if (serial <= 0)
        return NULL;

    return (task_key_object_t *)hashmap_get(&task_key_serial_map,
                                            task_key_serial_hash(serial));
}

static task_keyring_t *task_user_keyring_get_locked(int64_t uid, int64_t gid,
                                                    bool create) {
    task_keyring_t *ring = NULL;

    if (uid < 0)
        return NULL;

    ring = (task_keyring_t *)hashmap_get(&task_user_keyring_map, (uint64_t)uid);
    if (ring || !create)
        return ring;

    ring = task_keyring_alloc("_uid", uid, gid, true);
    if (!ring)
        return NULL;

    if (task_keyring_insert_object_locked(&ring->object) < 0 ||
        hashmap_put(&task_user_keyring_map, (uint64_t)uid, ring) < 0) {
        task_key_object_destroy_locked(&ring->object);
        return NULL;
    }

    return ring;
}

static task_keyring_t *task_session_keyring_get_locked(task_t *task,
                                                       bool create) {
    task_keyring_t *ring;

    if (!task)
        return NULL;

    if (task->session_keyring)
        return task->session_keyring;
    if (!create)
        return NULL;

    ring = task_keyring_alloc("_ses", task->uid, task->gid, false);
    if (!ring)
        return NULL;

    ring->object.ref_count = 1;
    if (task_keyring_insert_object_locked(&ring->object) < 0) {
        task_key_object_destroy_locked(&ring->object);
        return NULL;
    }

    task->session_keyring = ring;
    return ring;
}

static task_keyring_t *
task_keyring_resolve_locked(task_t *task, key_serial_t serial, bool create) {
    task_key_object_t *object;

    if (!task)
        return NULL;

    switch (serial) {
    case KEY_SPEC_THREAD_KEYRING:
    case KEY_SPEC_PROCESS_KEYRING:
    case KEY_SPEC_SESSION_KEYRING:
        return task_session_keyring_get_locked(task, create);
    case KEY_SPEC_USER_KEYRING:
    case KEY_SPEC_USER_SESSION_KEYRING:
        return task_user_keyring_get_locked(task->uid, task->gid, create);
    default:
        object = task_key_lookup_locked(serial);
        if (!object || object->type != TASK_KEY_OBJECT_KEYRING)
            return NULL;
        return (task_keyring_t *)object;
    }
}

static task_key_object_t *task_key_object_resolve_locked(task_t *task,
                                                         key_serial_t serial,
                                                         bool create_keyrings) {
    if (serial < 0)
        return (task_key_object_t *)task_keyring_resolve_locked(
            task, serial, create_keyrings);
    return task_key_lookup_locked(serial);
}

static task_key_t *task_keyring_find_key_locked(task_keyring_t *ring,
                                                const char *type,
                                                const char *description,
                                                bool direct_only, int depth,
                                                uint64_t now_ns) {
    if (!ring || !type || !description || depth < 0)
        return NULL;

    for (size_t i = 0; i < ring->item_count; i++) {
        task_key_object_t *object = ring->items[i];

        if (!object || task_key_is_expired(object, now_ns))
            continue;

        if (object->type == TASK_KEY_OBJECT_KEY) {
            task_key_t *key = (task_key_t *)object;
            if (strcmp(key->key_type, type) == 0 &&
                strcmp(key->object.description, description) == 0) {
                return key;
            }
            continue;
        }

        if (!direct_only && depth > 0) {
            task_key_t *nested = task_keyring_find_key_locked(
                (task_keyring_t *)object, type, description, false, depth - 1,
                now_ns);
            if (nested)
                return nested;
        }
    }

    return NULL;
}

static bool task_keyring_contains_object_locked(task_keyring_t *ring,
                                                task_key_object_t *object) {
    if (!ring || !object)
        return false;

    for (size_t i = 0; i < ring->item_count; i++) {
        if (ring->items[i] == object)
            return true;
    }

    return false;
}

static int task_keyring_link_object_locked(task_keyring_t *ring,
                                           task_key_object_t *object) {
    int ret;

    if (!ring || !object)
        return -EINVAL;
    if (ring->object.serial == object->serial)
        return -EINVAL;
    if (task_keyring_contains_object_locked(ring, object))
        return 0;

    ret = task_keyring_ensure_capacity_locked(ring, ring->item_count + 1);
    if (ret < 0)
        return ret;

    task_key_object_get_locked(object);
    ring->items[ring->item_count++] = object;
    return 0;
}

static int task_keyring_unlink_object_locked(task_keyring_t *ring,
                                             task_key_object_t *object) {
    if (!ring || !object)
        return -EINVAL;

    for (size_t i = 0; i < ring->item_count; i++) {
        if (ring->items[i] != object)
            continue;

        memmove(&ring->items[i], &ring->items[i + 1],
                (ring->item_count - i - 1) * sizeof(*ring->items));
        ring->item_count--;
        task_key_object_put_locked(object);
        return 0;
    }

    return -ENOENT;
}

static int task_keyring_copy_user_string(const char *user_str, char *buffer,
                                         size_t buffer_size) {
    if (!user_str || !buffer || buffer_size == 0)
        return -EINVAL;

    if (copy_from_user_str(buffer, user_str, buffer_size))
        return -EFAULT;

    if (buffer[0] == '\0')
        return -EINVAL;

    return 0;
}

static int task_keyctl_describe_copy(task_key_object_t *object, char **out,
                                     size_t *out_len) {
    const char *type_name = "keyring";
    char *buffer;
    int len;

    if (!object || !out || !out_len)
        return -EINVAL;

    if (object->type == TASK_KEY_OBJECT_KEY)
        type_name = ((task_key_t *)object)->key_type;

    len = snprintf(NULL, 0, "%s;%lld;%lld;%08x;%s", type_name,
                   (long long)object->uid, (long long)object->gid, object->perm,
                   object->description ? object->description : "");
    if (len < 0)
        return -EINVAL;

    buffer = malloc((size_t)len + 1);
    if (!buffer)
        return -ENOMEM;

    snprintf(buffer, (size_t)len + 1, "%s;%lld;%lld;%08x;%s", type_name,
             (long long)object->uid, (long long)object->gid, object->perm,
             object->description ? object->description : "");

    *out = buffer;
    *out_len = (size_t)len + 1;
    return 0;
}

static int task_keyctl_read_copy(task_key_object_t *object, void **out,
                                 size_t *out_len, uint64_t now_ns) {
    void *buffer = NULL;
    size_t len = 0;

    if (!object || !out || !out_len)
        return -EINVAL;

    if (task_key_is_expired(object, now_ns))
        return -ENOKEY;

    if (object->type == TASK_KEY_OBJECT_KEY) {
        task_key_t *key = (task_key_t *)object;

        if (key->payload_len > 0) {
            buffer = malloc(key->payload_len);
            if (!buffer)
                return -ENOMEM;
            memcpy(buffer, key->payload, key->payload_len);
        }

        *out = buffer;
        *out_len = key->payload_len;
        return 0;
    }

    task_keyring_t *ring = (task_keyring_t *)object;
    size_t live_count = 0;

    for (size_t i = 0; i < ring->item_count; i++) {
        if (ring->items[i] && !task_key_is_expired(ring->items[i], now_ns))
            live_count++;
    }

    len = live_count * sizeof(key_serial_t);
    if (len > 0) {
        key_serial_t *serials = malloc(len);
        if (!serials)
            return -ENOMEM;

        size_t index = 0;
        for (size_t i = 0; i < ring->item_count; i++) {
            if (!ring->items[i] || task_key_is_expired(ring->items[i], now_ns))
                continue;
            serials[index++] = ring->items[i]->serial;
        }

        buffer = serials;
    }

    *out = buffer;
    *out_len = len;
    return 0;
}

void task_keyring_inherit(task_t *child, task_t *parent) {
    if (!child || !parent)
        return;

    spin_lock(&task_keyring_lock);
    child->session_keyring = parent->session_keyring;
    if (child->session_keyring)
        task_key_object_get_locked(&child->session_keyring->object);
    spin_unlock(&task_keyring_lock);
}

void task_keyring_release_task(task_t *task) {
    task_keyring_t *ring;

    if (!task)
        return;

    spin_lock(&task_keyring_lock);
    ring = task->session_keyring;
    task->session_keyring = NULL;
    if (ring)
        task_key_object_put_locked(&ring->object);
    spin_unlock(&task_keyring_lock);
}

uint64_t sys_add_key(const char *type, const char *description,
                     const void *payload, size_t plen, key_serial_t ringid) {
    char type_buf[TASK_KEY_TYPE_MAX];
    char desc_buf[TASK_KEY_DESC_MAX];
    task_key_t *new_key = NULL;
    task_keyring_t *ring;
    task_key_t *existing;
    uint64_t now_ns = nano_time();
    int ret;

    if (!current_task)
        return (uint64_t)-ESRCH;
    if (plen > TASK_KEY_PAYLOAD_MAX)
        return (uint64_t)-E2BIG;

    ret = task_keyring_copy_user_string(type, type_buf, sizeof(type_buf));
    if (ret < 0)
        return (uint64_t)ret;

    ret =
        task_keyring_copy_user_string(description, desc_buf, sizeof(desc_buf));
    if (ret < 0)
        return (uint64_t)ret;

    if (plen > 0) {
        if (!payload || check_user_overflow((uint64_t)payload, plen))
            return (uint64_t)-EFAULT;
        new_key = task_key_alloc(type_buf, desc_buf, current_task->euid,
                                 current_task->egid, payload, plen);
    } else {
        new_key = task_key_alloc(type_buf, desc_buf, current_task->euid,
                                 current_task->egid, NULL, 0);
    }

    if (!new_key)
        return (uint64_t)-ENOMEM;

    spin_lock(&task_keyring_lock);

    ring = task_keyring_resolve_locked(current_task, ringid, true);
    if (!ring) {
        spin_unlock(&task_keyring_lock);
        free(new_key->payload);
        free(new_key->key_type);
        free(new_key->object.description);
        free(new_key);
        return (uint64_t)-ENOKEY;
    }

    existing =
        task_keyring_find_key_locked(ring, type_buf, desc_buf, true, 0, now_ns);
    if (existing) {
        free(existing->payload);
        existing->payload = new_key->payload;
        existing->payload_len = new_key->payload_len;
        existing->object.uid = current_task->euid;
        existing->object.gid = current_task->egid;
        existing->object.expiry_ns = 0;
        spin_unlock(&task_keyring_lock);

        free(new_key->key_type);
        free(new_key->object.description);
        free(new_key);
        return existing->object.serial;
    }

    ret = task_keyring_insert_object_locked(&new_key->object);
    if (ret < 0)
        goto fail_locked;

    ret = task_keyring_link_object_locked(ring, &new_key->object);
    if (ret < 0) {
        hashmap_remove(&task_key_serial_map,
                       task_key_serial_hash(new_key->object.serial));
        goto fail_locked;
    }

    spin_unlock(&task_keyring_lock);
    return new_key->object.serial;

fail_locked:
    spin_unlock(&task_keyring_lock);
    free(new_key->payload);
    free(new_key->key_type);
    free(new_key->object.description);
    free(new_key);
    return (uint64_t)ret;
}

uint64_t sys_request_key(const char *type, const char *description,
                         const char *callout_info, key_serial_t dest_keyring) {
    char type_buf[TASK_KEY_TYPE_MAX];
    char desc_buf[TASK_KEY_DESC_MAX];
    task_key_t *key = NULL;
    task_keyring_t *session_ring;
    task_keyring_t *user_ring;
    uint64_t now_ns = nano_time();
    int ret;

    (void)callout_info;
    (void)dest_keyring;

    if (!current_task)
        return (uint64_t)-ESRCH;

    ret = task_keyring_copy_user_string(type, type_buf, sizeof(type_buf));
    if (ret < 0)
        return (uint64_t)ret;

    ret =
        task_keyring_copy_user_string(description, desc_buf, sizeof(desc_buf));
    if (ret < 0)
        return (uint64_t)ret;

    spin_lock(&task_keyring_lock);

    session_ring = task_keyring_resolve_locked(current_task,
                                               KEY_SPEC_SESSION_KEYRING, false);
    if (session_ring)
        key = task_keyring_find_key_locked(session_ring, type_buf, desc_buf,
                                           false, 4, now_ns);

    if (!key) {
        user_ring = task_keyring_resolve_locked(current_task,
                                                KEY_SPEC_USER_KEYRING, false);
        if (user_ring)
            key = task_keyring_find_key_locked(user_ring, type_buf, desc_buf,
                                               false, 1, now_ns);
    }

    spin_unlock(&task_keyring_lock);

    return key ? (uint64_t)key->object.serial : (uint64_t)-ENOKEY;
}

uint64_t sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3,
                    unsigned long arg4, unsigned long arg5) {
    task_key_object_t *object;
    task_key_object_t *target_object;
    task_keyring_t *ring;
    task_key_t *key;
    char type_buf[TASK_KEY_TYPE_MAX];
    char desc_buf[TASK_KEY_DESC_MAX];
    char name_buf[TASK_KEY_NAME_MAX];
    char *describe_buf = NULL;
    void *read_buf = NULL;
    size_t data_len = 0;
    size_t copy_len;
    uint64_t now_ns = nano_time();
    int ret;

    (void)arg5;

    if (!current_task)
        return (uint64_t)-ESRCH;

    switch (cmd) {
    case KEYCTL_GET_KEYRING_ID:
        spin_lock(&task_keyring_lock);
        ring = task_keyring_resolve_locked(current_task, (key_serial_t)arg2,
                                           arg3 != 0);
        ret = ring ? ring->object.serial : -ENOKEY;
        spin_unlock(&task_keyring_lock);
        return (uint64_t)ret;

    case KEYCTL_JOIN_SESSION_KEYRING: {
        task_keyring_t *new_ring;
        task_keyring_t *old_ring;
        const char *name_user = (const char *)arg2;

        if (name_user != NULL) {
            ret = task_keyring_copy_user_string(name_user, name_buf,
                                                sizeof(name_buf));
            if (ret < 0)
                return (uint64_t)ret;
        } else {
            strcpy(name_buf, "_ses");
        }

        new_ring = task_keyring_alloc(name_buf, current_task->uid,
                                      current_task->gid, false);
        if (!new_ring)
            return (uint64_t)-ENOMEM;

        new_ring->object.ref_count = 1;

        spin_lock(&task_keyring_lock);
        ret = task_keyring_insert_object_locked(&new_ring->object);
        if (ret < 0) {
            spin_unlock(&task_keyring_lock);
            free(new_ring->object.description);
            free(new_ring);
            return (uint64_t)ret;
        }

        old_ring = current_task->session_keyring;
        current_task->session_keyring = new_ring;
        if (old_ring)
            task_key_object_put_locked(&old_ring->object);
        spin_unlock(&task_keyring_lock);

        return new_ring->object.serial;
    }

    case KEYCTL_CHOWN:
    case KEYCTL_SETPERM:
    case KEYCTL_SET_TIMEOUT:
        spin_lock(&task_keyring_lock);
        object = task_key_object_resolve_locked(current_task,
                                                (key_serial_t)arg2, false);
        if (!object) {
            spin_unlock(&task_keyring_lock);
            return (uint64_t)-ENOKEY;
        }

        if (cmd == KEYCTL_CHOWN) {
            int32_t uid = (int32_t)arg3;
            int32_t gid = (int32_t)arg4;
            if (uid != -1)
                object->uid = uid;
            if (gid != -1)
                object->gid = gid;
        } else if (cmd == KEYCTL_SETPERM) {
            object->perm = (uint32_t)arg3;
        } else {
            unsigned long seconds = arg3;
            object->expiry_ns =
                seconds == 0 ? 0 : now_ns + seconds * 1000000000ULL;
        }

        spin_unlock(&task_keyring_lock);
        return 0;

    case KEYCTL_LINK:
    case KEYCTL_UNLINK:
        spin_lock(&task_keyring_lock);
        object = task_key_object_resolve_locked(current_task,
                                                (key_serial_t)arg2, false);
        target_object = task_key_object_resolve_locked(
            current_task, (key_serial_t)arg3, false);
        if (!object || !target_object ||
            target_object->type != TASK_KEY_OBJECT_KEYRING) {
            spin_unlock(&task_keyring_lock);
            return (uint64_t)-ENOKEY;
        }

        if (cmd == KEYCTL_LINK)
            ret = task_keyring_link_object_locked(
                (task_keyring_t *)target_object, object);
        else
            ret = task_keyring_unlink_object_locked(
                (task_keyring_t *)target_object, object);

        spin_unlock(&task_keyring_lock);
        return (uint64_t)ret;

    case KEYCTL_SEARCH:
        ret = task_keyring_copy_user_string((const char *)arg3, type_buf,
                                            sizeof(type_buf));
        if (ret < 0)
            return (uint64_t)ret;
        ret = task_keyring_copy_user_string((const char *)arg4, desc_buf,
                                            sizeof(desc_buf));
        if (ret < 0)
            return (uint64_t)ret;

        spin_lock(&task_keyring_lock);
        ring = task_keyring_resolve_locked(current_task, (key_serial_t)arg2,
                                           false);
        key = ring ? task_keyring_find_key_locked(ring, type_buf, desc_buf,
                                                  false, 4, now_ns)
                   : NULL;
        spin_unlock(&task_keyring_lock);
        return key ? (uint64_t)key->object.serial : (uint64_t)-ENOKEY;

    case KEYCTL_DESCRIBE:
        spin_lock(&task_keyring_lock);
        object = task_key_object_resolve_locked(current_task,
                                                (key_serial_t)arg2, false);
        if (!object) {
            spin_unlock(&task_keyring_lock);
            return (uint64_t)-ENOKEY;
        }
        ret = task_keyctl_describe_copy(object, &describe_buf, &data_len);
        spin_unlock(&task_keyring_lock);
        if (ret < 0)
            return (uint64_t)ret;

        copy_len = MIN((size_t)arg4, data_len);
        if ((const void *)arg3 != NULL && copy_len > 0 &&
            copy_to_user((void *)arg3, describe_buf, copy_len)) {
            free(describe_buf);
            return (uint64_t)-EFAULT;
        }

        free(describe_buf);
        return data_len;

    case KEYCTL_READ:
        spin_lock(&task_keyring_lock);
        object = task_key_object_resolve_locked(current_task,
                                                (key_serial_t)arg2, false);
        if (!object) {
            spin_unlock(&task_keyring_lock);
            return (uint64_t)-ENOKEY;
        }
        ret = task_keyctl_read_copy(object, &read_buf, &data_len, now_ns);
        spin_unlock(&task_keyring_lock);
        if (ret < 0)
            return (uint64_t)ret;

        copy_len = MIN((size_t)arg4, data_len);
        if ((const void *)arg3 != NULL && copy_len > 0 &&
            copy_to_user((void *)arg3, read_buf, copy_len)) {
            free(read_buf);
            return (uint64_t)-EFAULT;
        }

        free(read_buf);
        return data_len;

    default:
        return (uint64_t)-EOPNOTSUPP;
    }
}
