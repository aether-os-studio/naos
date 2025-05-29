#pragma once

#include <libs/klibc.h>

typedef struct
{
    uint8_t addressid;
    uint8_t register_bitwidth;
    uint8_t register_bitoffset;
    uint8_t access_size;
    uint64_t address;
} acpi_address_t;

struct ACPISDTHeader
{
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oemid[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
};

typedef struct
{
    char signature[8];         // 签名
    uint8_t checksum;          // 校验和
    char oem_id[6];            // OEM ID
    uint8_t revision;          // 版本
    uint32_t rsdt_address;     // V1: RSDT 地址 (32-bit)
    uint32_t length;           // 结构体长度
    uint64_t xsdt_address;     // V2: XSDT 地址 (64-bit)
    uint8_t extended_checksum; // 扩展校验和
    uint8_t reserved[3];       // 保留字段
} __attribute__((packed)) RSDP;

typedef struct
{
    struct ACPISDTHeader h;
    uint64_t PointerToOtherSDT;
} __attribute__((packed)) XSDT;

typedef struct
{
    struct ACPISDTHeader h;
    uint32_t local_apic_address;
    uint32_t flags;
    void *entries;
} __attribute__((packed)) MADT;

typedef struct madt_header
{
    uint8_t entry_type;
    uint8_t length;
} __attribute__((packed)) MadtHeader;

#define ACPI_MADT_TYPE_GICC 0x0B
#define ACPI_MADT_TYPE_GICD 0x0C
#define ACPI_MADT_TYPE_GICR 0x0E

typedef struct gicc_entry
{
    struct madt_header header;
    uint8_t reserved1[2];
    uint32_t iface_no;
    uint32_t acpi_uid;
    uint32_t flags;
    uint32_t parking_ver;
    uint32_t perf_gsiv;
    uint64_t parking_addr;
    uint64_t gicc_base_addr;
    uint64_t gicv_base_addr;
    uint64_t gich_base_addr;
    uint32_t vgic_maint_gsiv;
    uint64_t gicr_base_addr;
    uint64_t mpidr;
    uint8_t power_eff_class;
    uint8_t reserved2;
    uint16_t spe_overflow_gsiv;
} __attribute__((packed)) GiccEntry;

typedef struct gicd_entry
{
    struct madt_header h;
    uint16_t reserved1;
    uint32_t gic_id;
    uint64_t base_address;
    uint32_t gic_version;
    uint8_t reserved2[3];
} __attribute__((packed)) GicdEntry;

typedef struct gicr_entry
{
    struct madt_header h;
    uint16_t _reserved;
    uint64_t discovery_range_base_address;
    uint32_t discovery_range_length;
} __attribute__((packed)) GicrEntry;

typedef struct
{
    struct ACPISDTHeader header;
    uint64_t Reserved;
} __attribute__((packed)) MCFG;

typedef struct
{
    uint64_t base_address;
    uint16_t pci_segment_group;
    uint8_t start_bus;
    uint8_t end_bus;
    uint32_t reserved;
} __attribute__((packed)) MCFG_ENTRY;

struct generic_address
{
    uint8_t address_space;
    uint8_t bit_width;
    uint8_t bit_offset;
    uint8_t access_size;
    uint64_t address;
} __attribute__((packed));

typedef struct
{
    struct ACPISDTHeader Header;
    uint8_t iface_type;
    uint8_t reserved0[3];
    struct generic_address address;
    uint8_t interrupt_type;
    uint8_t irq;
    uint32_t global_system_interrupt;
    uint8_t configured_baud_rate;
    uint8_t parity;
    uint8_t stop_bits;
    uint8_t flow_control;
    uint8_t terminal_type;
    uint8_t language;
    uint16_t pci_device_id;
    uint16_t pci_vendor_id;
    uint8_t pci_bus_num;
    uint8_t pci_device_num;
    uint8_t pci_function_num;
    uint32_t pci_flags;
    uint8_t pci_segment;
    uint32_t uart_clock_freq;
    uint32_t precise_baud_rate;
    uint16_t namespace_string_length;
    uint16_t namespace_string_offset;
} __attribute__((packed)) SPCR;

void acpi_init();

void madt_setup(MADT *madt);

uint64_t nanoTime();
