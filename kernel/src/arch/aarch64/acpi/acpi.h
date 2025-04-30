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
    char Signature[4];
    uint32_t Length;
    uint8_t Revision;
    uint8_t Checksum;
    char OEMID[6];
    char OEMTableID[8];
    uint32_t OEMRevision;
    uint32_t CreatorID;
    uint32_t CreatorRevision;
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

#define ACPI_MADT_TYPE_GICD 0x0C
#define ACPI_MADT_TYPE_GICR 0x0E

typedef struct gicd_entry
{
    struct madt_header h;
    uint16_t reserved1;
    uint32_t gic_id;
    uint64_t base_address;
    uint32_t gic_version;
    uint8_t reserved2[3];
} __attribute__((packed)) GicdEntry;

void acpi_init();

void madt_setup(MADT *madt);
