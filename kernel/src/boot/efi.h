#pragma once

#include <libs/klibc.h>

typedef uint64_t efi_status_t;
typedef uint64_t efi_physical_address_t;
typedef uint64_t efi_virtual_address_t;
typedef void *efi_handle_t;

typedef struct efi_table_header {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
} efi_table_header_t;

typedef struct efi_guid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} efi_guid_t;

typedef enum efi_reset_type {
    EFI_RESET_COLD = 0,
    EFI_RESET_WARM = 1,
    EFI_RESET_SHUTDOWN = 2,
    EFI_RESET_PLATFORM_SPECIFIC = 3,
} efi_reset_type_t;

typedef void (*efi_reset_system_t)(efi_reset_type_t reset_type,
                                   efi_status_t reset_status, size_t data_size,
                                   void *reset_data);

typedef struct efi_configuration_table {
    efi_guid_t vendor_guid;
    void *vendor_table;
} efi_configuration_table_t;

typedef struct efi_memory_descriptor {
    uint32_t type;
    uint32_t pad;
    efi_physical_address_t physical_start;
    efi_virtual_address_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} efi_memory_descriptor_t;

typedef efi_status_t (*efi_get_memory_map_t)(
    size_t *memory_map_size, efi_memory_descriptor_t *memory_map,
    size_t *map_key, size_t *descriptor_size, uint32_t *descriptor_version);

typedef struct efi_boot_services {
    efi_table_header_t hdr;
    char _pad1[240 - sizeof(efi_table_header_t)];
    efi_get_memory_map_t get_memory_map;
} efi_boot_services_t;

typedef struct efi_runtime_services {
    efi_table_header_t hdr;
    void *get_time;
    void *set_time;
    void *get_wakeup_time;
    void *set_wakeup_time;
    void *set_virtual_address_map;
    void *convert_pointer;
    void *get_variable;
    void *get_next_variable_name;
    void *set_variable;
    void *get_next_high_mono_count;
    efi_reset_system_t reset_system;
} efi_runtime_services_t;

typedef struct efi_system_table {
    efi_table_header_t hdr;
    uint16_t *firmware_vendor;
    uint32_t firmware_revision;
    efi_handle_t console_in_handle;
    void *con_in;
    efi_handle_t console_out_handle;
    void *con_out;
    efi_handle_t standard_error_handle;
    void *std_err;
    efi_runtime_services_t *runtime_services;
    efi_boot_services_t *boot_services;
    size_t number_of_table_entries;
    efi_configuration_table_t *configuration_table;
} efi_system_table_t;
