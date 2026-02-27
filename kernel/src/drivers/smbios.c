#include <drivers/smbios.h>

#include <boot/boot.h>
#include <drivers/kernel_logger.h>
#include <mm/mm.h>

#define SMBIOS_MAX_TABLE_BYTES (16u * 1024u * 1024u)

struct smbios_entry32 {
    char anchor[4];
    uint8_t checksum;
    uint8_t length;
    uint8_t major;
    uint8_t minor;
    uint16_t max_structure_size;
    uint8_t entry_point_revision;
    uint8_t formatted_area[5];
    char intermediate_anchor[5];
    uint8_t intermediate_checksum;
    uint16_t table_length;
    uint32_t table_address;
    uint16_t structure_count;
    uint8_t bcd_revision;
} __attribute__((packed));

struct smbios_entry64 {
    char anchor[5];
    uint8_t checksum;
    uint8_t length;
    uint8_t major;
    uint8_t minor;
    uint8_t docrev;
    uint8_t entry_point_revision;
    uint8_t reserved;
    uint32_t table_max_size;
    uint64_t table_address;
} __attribute__((packed));

struct smbios_type0 {
    smbios_structure_header_t hdr;
    uint8_t vendor;
    uint8_t bios_version;
    uint16_t bios_starting_address_segment;
    uint8_t bios_release_date;
    uint8_t bios_rom_size;
} __attribute__((packed));

struct smbios_type1 {
    smbios_structure_header_t hdr;
    uint8_t manufacturer;
    uint8_t product_name;
    uint8_t version;
    uint8_t serial_number;
    uint8_t uuid[16];
    uint8_t wake_up_type;
} __attribute__((packed));

typedef struct smbios_context {
    bool initialized;
    bool available;
    int last_error;
    uint8_t major;
    uint8_t minor;
    const uint8_t *table_start;
    size_t table_length;
} smbios_context_t;

static smbios_context_t g_smbios;

static bool smbios_is_range_mapped(const void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return false;
    }

    uint64_t *pgdir = get_current_page_dir(false);
    uintptr_t start = PADDING_DOWN((uintptr_t)ptr, DEFAULT_PAGE_SIZE);
    uintptr_t end = PADDING_UP((uintptr_t)ptr + len, DEFAULT_PAGE_SIZE);

    for (uintptr_t va = start; va < end; va += DEFAULT_PAGE_SIZE) {
        if (translate_address(pgdir, va) == 0) {
            return false;
        }
    }

    return true;
}

static uintptr_t smbios_guess_phys_addr(const void *ptr) {
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t hhdm = (uintptr_t)boot_get_hhdm_offset();

    if (addr >= hhdm) {
        return addr - hhdm;
    }

    return addr;
}

static const void *smbios_map_phys_window(uintptr_t phys_addr, size_t len) {
    if (phys_addr == 0 || len == 0) {
        return NULL;
    }

    uintptr_t hhdm = (uintptr_t)boot_get_hhdm_offset();
    uintptr_t phys_base = PADDING_DOWN(phys_addr, DEFAULT_PAGE_SIZE);
    uintptr_t phys_end = PADDING_UP(phys_addr + len, DEFAULT_PAGE_SIZE);
    uintptr_t map_len = phys_end - phys_base;
    uintptr_t virt_base = hhdm + phys_base;

    map_page_range(get_current_page_dir(false), virt_base, phys_base, map_len,
                   PT_FLAG_R | PT_FLAG_W);

    return (const void *)(hhdm + phys_addr);
}

static bool smbios_checksum_valid(const uint8_t *data, size_t len) {
    uint8_t sum = 0;

    for (size_t i = 0; i < len; i++) {
        sum = (uint8_t)(sum + data[i]);
    }

    return sum == 0;
}

static const uint8_t *smbios_table_end(void) {
    return g_smbios.table_start + g_smbios.table_length;
}

static bool smbios_header_in_bounds(const smbios_structure_header_t *header) {
    const uint8_t *start = g_smbios.table_start;
    const uint8_t *end = smbios_table_end();
    const uint8_t *hdr = (const uint8_t *)header;

    if (!header || hdr < start || hdr >= end) {
        return false;
    }

    if ((size_t)(end - hdr) < sizeof(*header)) {
        return false;
    }

    if (header->length < sizeof(*header) ||
        (size_t)(end - hdr) < header->length) {
        return false;
    }

    return true;
}

static const uint8_t *smbios_next_raw(const uint8_t *current) {
    const uint8_t *end = smbios_table_end();

    if (!current || current >= end) {
        return NULL;
    }

    if ((size_t)(end - current) < sizeof(smbios_structure_header_t)) {
        return NULL;
    }

    const smbios_structure_header_t *header =
        (const smbios_structure_header_t *)current;
    if (header->length < sizeof(*header) ||
        (size_t)(end - current) < header->length) {
        return NULL;
    }

    const uint8_t *string_area = current + header->length;
    for (const uint8_t *p = string_area; (size_t)(end - p) >= 2; p++) {
        if (p[0] == 0 && p[1] == 0) {
            const uint8_t *next = p + 2;
            if (next > end) {
                return NULL;
            }
            return next;
        }
    }

    return NULL;
}

static int smbios_configure_from_entry32(const struct smbios_entry32 *entry) {
    if (!entry) {
        return -ENOENT;
    }

    if (memcmp(entry->anchor, "_SM_", 4) != 0) {
        return -EINVAL;
    }

    if (entry->length < sizeof(struct smbios_entry32)) {
        return -EINVAL;
    }

    if (!smbios_checksum_valid((const uint8_t *)entry, entry->length)) {
        return -EINVAL;
    }

    if (memcmp(entry->intermediate_anchor, "_DMI_", 5) != 0) {
        return -EINVAL;
    }

    if (!smbios_checksum_valid(
            (const uint8_t *)entry->intermediate_anchor,
            sizeof(entry->intermediate_anchor) +
                sizeof(entry->intermediate_checksum) +
                sizeof(entry->table_length) + sizeof(entry->table_address) +
                sizeof(entry->structure_count) + sizeof(entry->bcd_revision))) {
        return -EINVAL;
    }

    if (entry->table_length == 0) {
        return -EINVAL;
    }

    g_smbios.major = entry->major;
    g_smbios.minor = entry->minor;
    g_smbios.table_start = (const uint8_t *)smbios_map_phys_window(
        (uintptr_t)entry->table_address, entry->table_length);
    if (!g_smbios.table_start) {
        return -EINVAL;
    }
    g_smbios.table_length = entry->table_length;

    return 0;
}

static int smbios_configure_from_entry64(const struct smbios_entry64 *entry) {
    if (!entry) {
        return -ENOENT;
    }

    if (memcmp(entry->anchor, "_SM3_", 5) != 0) {
        return -EINVAL;
    }

    if (entry->length < sizeof(struct smbios_entry64)) {
        return -EINVAL;
    }

    if (!smbios_checksum_valid((const uint8_t *)entry, entry->length)) {
        return -EINVAL;
    }

    if (entry->table_max_size == 0 ||
        entry->table_max_size > SMBIOS_MAX_TABLE_BYTES) {
        return -EINVAL;
    }

    g_smbios.major = entry->major;
    g_smbios.minor = entry->minor;
    g_smbios.table_start = (const uint8_t *)smbios_map_phys_window(
        (uintptr_t)entry->table_address, entry->table_max_size);
    if (!g_smbios.table_start) {
        return -EINVAL;
    }
    g_smbios.table_length = entry->table_max_size;

    return 0;
}

static int smbios_validate_table(void) {
    const uint8_t *entry = g_smbios.table_start;
    const uint8_t *end = smbios_table_end();
    size_t guard = 0;

    if (!entry || g_smbios.table_length < sizeof(smbios_structure_header_t)) {
        return -EINVAL;
    }

    while (entry < end && guard++ < 8192) {
        if ((size_t)(end - entry) < sizeof(smbios_structure_header_t)) {
            return -EINVAL;
        }

        const smbios_structure_header_t *header =
            (const smbios_structure_header_t *)entry;
        const uint8_t *next = smbios_next_raw(entry);
        if (!next) {
            return -EINVAL;
        }

        if (header->type == 127) {
            return 0;
        }

        entry = next;
    }

    return -EINVAL;
}

#if defined(__x86_64__)
static int smbios_scan_legacy_entry(void) {
    const uint64_t hhdm = boot_get_hhdm_offset();
    map_page_range(get_current_page_dir(false), hhdm + 0x000F0000u, 0x000F0000u,
                   0x00010000u, PT_FLAG_R | PT_FLAG_W);
    const uint8_t *start = (const uint8_t *)(uintptr_t)(hhdm + 0x000F0000u);
    const uint8_t *end = (const uint8_t *)(uintptr_t)(hhdm + 0x00100000u);

    for (const uint8_t *p = start; p < end; p += 16) {
        if ((size_t)(end - p) >= sizeof(struct smbios_entry64) &&
            memcmp(p, "_SM3_", 5) == 0) {
            int ret =
                smbios_configure_from_entry64((const struct smbios_entry64 *)p);
            if (ret == 0) {
                return 0;
            }
        }

        if ((size_t)(end - p) >= sizeof(struct smbios_entry32) &&
            memcmp(p, "_SM_", 4) == 0) {
            int ret =
                smbios_configure_from_entry32((const struct smbios_entry32 *)p);
            if (ret == 0) {
                return 0;
            }
        }
    }

    return -ENOENT;
}
#endif

int smbios_init(void) {
    void *entry32 = NULL;
    void *entry64 = NULL;
    const struct smbios_entry32 *entry32_mapped = NULL;
    const struct smbios_entry64 *entry64_mapped = NULL;

    g_smbios.initialized = true;
    g_smbios.available = false;
    g_smbios.last_error = -ENOENT;
    g_smbios.major = 0;
    g_smbios.minor = 0;
    g_smbios.table_start = NULL;
    g_smbios.table_length = 0;

    boot_get_smbios_entries(&entry32, &entry64);

    if (entry64 &&
        smbios_is_range_mapped(entry64, sizeof(struct smbios_entry64))) {
        g_smbios.last_error = smbios_configure_from_entry64(
            (const struct smbios_entry64 *)entry64);
    } else if (entry64) {
        entry64_mapped = (const struct smbios_entry64 *)smbios_map_phys_window(
            smbios_guess_phys_addr(entry64), sizeof(struct smbios_entry64));
        if (entry64_mapped) {
            g_smbios.last_error = smbios_configure_from_entry64(entry64_mapped);
        }
    }

    if (g_smbios.last_error != 0 && entry32 &&
        smbios_is_range_mapped(entry32, sizeof(struct smbios_entry32))) {
        g_smbios.last_error = smbios_configure_from_entry32(
            (const struct smbios_entry32 *)entry32);
    } else if (g_smbios.last_error != 0 && entry32) {
        entry32_mapped = (const struct smbios_entry32 *)smbios_map_phys_window(
            smbios_guess_phys_addr(entry32), sizeof(struct smbios_entry32));
        if (entry32_mapped) {
            g_smbios.last_error = smbios_configure_from_entry32(entry32_mapped);
        }
    }

#if defined(__x86_64__)
    if (g_smbios.last_error != 0) {
        g_smbios.last_error = smbios_scan_legacy_entry();
    }
#endif

    if (g_smbios.last_error == 0) {
        g_smbios.last_error = smbios_validate_table();
    }

    if (g_smbios.last_error != 0) {
        printk("SMBIOS: unavailable or invalid (%d)\n", g_smbios.last_error);
        return g_smbios.last_error;
    }

    g_smbios.available = true;

    printk("SMBIOS: version %u.%u table=%p size=%zu\n", g_smbios.major,
           g_smbios.minor, g_smbios.table_start, g_smbios.table_length);
    return 0;
}

bool smbios_available(void) { return g_smbios.available; }

int smbios_last_error(void) { return g_smbios.last_error; }

uint8_t smbios_major_version(void) { return g_smbios.major; }

uint8_t smbios_minor_version(void) { return g_smbios.minor; }

const smbios_structure_header_t *smbios_first(void) {
    if (!g_smbios.available || !g_smbios.table_start) {
        return NULL;
    }

    const smbios_structure_header_t *header =
        (const smbios_structure_header_t *)g_smbios.table_start;
    if (!smbios_header_in_bounds(header)) {
        return NULL;
    }

    return header;
}

const smbios_structure_header_t *
smbios_next(const smbios_structure_header_t *current) {
    if (!current) {
        return smbios_first();
    }

    if (!g_smbios.available || !smbios_header_in_bounds(current)) {
        return NULL;
    }

    const uint8_t *next = smbios_next_raw((const uint8_t *)current);
    if (!next || next >= smbios_table_end()) {
        return NULL;
    }

    const smbios_structure_header_t *next_header =
        (const smbios_structure_header_t *)next;
    if (!smbios_header_in_bounds(next_header)) {
        return NULL;
    }

    return next_header;
}

const smbios_structure_header_t *smbios_find_type(uint8_t type, size_t index) {
    size_t found = 0;

    for (const smbios_structure_header_t *hdr = smbios_first(); hdr;
         hdr = smbios_next(hdr)) {
        if (hdr->type == type) {
            if (found == index) {
                return hdr;
            }
            found++;
        }

        if (hdr->type == 127) {
            break;
        }
    }

    return NULL;
}

const char *smbios_string(const smbios_structure_header_t *header,
                          uint8_t string_index) {
    static const char empty[] = "";

    if (!g_smbios.available || !smbios_header_in_bounds(header)) {
        return NULL;
    }

    if (string_index == 0) {
        return empty;
    }

    const uint8_t *end = smbios_table_end();
    const char *str = (const char *)((const uint8_t *)header + header->length);
    uint8_t current_index = 1;

    while ((const uint8_t *)str < end) {
        size_t len = strnlen(str, (size_t)(end - (const uint8_t *)str));
        if ((const uint8_t *)str + len >= end) {
            return NULL;
        }

        if (len == 0) {
            return NULL;
        }

        if (current_index == string_index) {
            return str;
        }

        str += len + 1;
        current_index++;
    }

    return NULL;
}

int smbios_get_bios_info(smbios_bios_info_t *out) {
    if (!out) {
        return -EINVAL;
    }

    memset(out, 0, sizeof(*out));

    const smbios_structure_header_t *hdr = smbios_find_type(0, 0);
    if (!hdr) {
        return -ENOENT;
    }

    if (hdr->length < sizeof(struct smbios_type0)) {
        return -EINVAL;
    }

    const struct smbios_type0 *bios = (const struct smbios_type0 *)hdr;

    out->vendor = smbios_string(hdr, bios->vendor);
    out->version = smbios_string(hdr, bios->bios_version);
    out->release_date = smbios_string(hdr, bios->bios_release_date);

    return 0;
}

int smbios_get_system_info(smbios_system_info_t *out) {
    if (!out) {
        return -EINVAL;
    }

    memset(out, 0, sizeof(*out));

    const smbios_structure_header_t *hdr = smbios_find_type(1, 0);
    if (!hdr) {
        return -ENOENT;
    }

    if (hdr->length < sizeof(struct smbios_type1)) {
        return -EINVAL;
    }

    const struct smbios_type1 *sys = (const struct smbios_type1 *)hdr;

    out->manufacturer = smbios_string(hdr, sys->manufacturer);
    out->product_name = smbios_string(hdr, sys->product_name);
    out->version = smbios_string(hdr, sys->version);
    out->serial_number = smbios_string(hdr, sys->serial_number);
    out->wake_up_type = sys->wake_up_type;
    memcpy(out->uuid, sys->uuid, sizeof(out->uuid));

    return 0;
}
