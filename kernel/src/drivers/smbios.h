#pragma once

#include <libs/klibc.h>

typedef struct smbios_structure_header {
    uint8_t type;
    uint8_t length;
    uint16_t handle;
} __attribute__((packed)) smbios_structure_header_t;

typedef struct smbios_bios_info {
    const char *vendor;
    const char *version;
    const char *release_date;
} smbios_bios_info_t;

typedef struct smbios_system_info {
    const char *manufacturer;
    const char *product_name;
    const char *version;
    const char *serial_number;
    uint8_t wake_up_type;
    uint8_t uuid[16];
} smbios_system_info_t;

int smbios_init(void);
bool smbios_available(void);
int smbios_last_error(void);

uint8_t smbios_major_version(void);
uint8_t smbios_minor_version(void);

const smbios_structure_header_t *smbios_first(void);
const smbios_structure_header_t *
smbios_next(const smbios_structure_header_t *current);
const smbios_structure_header_t *smbios_find_type(uint8_t type, size_t index);

const char *smbios_string(const smbios_structure_header_t *header,
                          uint8_t string_index);

int smbios_get_bios_info(smbios_bios_info_t *out);
int smbios_get_system_info(smbios_system_info_t *out);
