#pragma once

#include <libs/klibc.h>

typedef struct {
    uint8_t addressid;
    uint8_t register_bitwidth;
    uint8_t register_bitoffset;
    uint8_t access_size;
    uint64_t address;
} acpi_address_t;

struct ACPISDTheader {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oemid[6];
    char oemtableid[8];
    uint32_t oemrevision;
    uint32_t creatorid;
    uint32_t creator_revsion;
};

typedef struct {
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

typedef struct {
    struct ACPISDTheader h;
    uint64_t pointer_to_other_sdt;
} __attribute__((packed)) XSDT;

typedef struct {
    struct ACPISDTheader h;
    uint32_t local_apic_address;
    uint32_t flags;
    void *entries;
} __attribute__((packed)) MADT;

struct madt_header {
    uint8_t entry_type;
    uint8_t length;
} __attribute__((packed));

struct madt_io_apic {
    struct madt_header h;
    uint8_t apic_id;
    uint8_t reserved;
    uint32_t address;
    uint32_t gsib;
} __attribute__((packed));

struct madt_local_apic {
    struct madt_header h;
    uint8_t acpi_processor_uid;
    uint8_t local_apic_id;
    uint32_t flags;
};

/* MADT子表类型定义 - RISC-V特定 */
#define ACPI_MADT_TYPE_RINTC 0x18  /* RISC-V INTC */
#define ACPI_MADT_TYPE_RIMSIC 0x19 /* RISC-V IMSIC */
#define ACPI_MADT_TYPE_RAPLIC 0x1A /* RISC-V APLIC */
#define ACPI_MADT_TYPE_RPLIC 0x1B  /* RISC-V PLIC */

/* RISC-V INTC (Hart-Level Interrupt Controller) 结构 */
struct acpi_madt_rintc {
    struct madt_header header;
    uint8_t version;
    uint8_t reserved;
    uint32_t flags;
    uint64_t hart_id;     /* Hart ID */
    uint32_t uid;         /* ACPI处理器UID */
    uint32_t ext_intc_id; /* 外部中断控制器ID，指向IMSIC */
    uint64_t imsic_addr;  /* IMSIC基地址（如果有） */
    uint32_t imsic_size;  /* IMSIC大小 */
} __attribute__((packed));

/* RISC-V INTC标志位 */
#define ACPI_MADT_RINTC_ENABLED (1 << 0)
#define ACPI_MADT_RINTC_ONLINE_CAPABLE (1 << 1)

/* RISC-V APLIC (Advanced Platform-Level Interrupt Controller) 结构 */
struct acpi_madt_raplic {
    struct madt_header header;
    uint8_t version;
    uint8_t id; /* APLIC ID */
    uint32_t flags;
    uint8_t hw_id[8];     /* 硬件ID */
    uint16_t num_idcs;    /* 中断域配置数量 */
    uint16_t num_sources; /* 中断源数量 */
    uint32_t gsi_base;    /* 全局系统中断基址 */
    uint64_t base_addr;   /* APLIC基地址 */
    uint32_t size;        /* APLIC大小 */
} __attribute__((packed));

/* RISC-V PLIC (Platform-Level Interrupt Controller) 结构 */
struct acpi_madt_rplic {
    struct madt_header header;
    uint8_t version;
    uint8_t id;        /* PLIC ID */
    uint8_t hw_id[8];  /* 硬件ID */
    uint16_t num_irqs; /* 中断数量 */
    uint16_t max_prio; /* 最大优先级 */
    uint32_t flags;
    uint32_t size;      /* PLIC大小 */
    uint64_t base_addr; /* PLIC基地址 */
    uint32_t gsi_base;  /* 全局系统中断基址 */
} __attribute__((packed));

typedef struct {
    struct ACPISDTheader h;
    uint8_t definition_block;
} acpi_dsdt_t;

struct generic_address {
    uint8_t address_space;
    uint8_t bit_width;
    uint8_t bit_offset;
    uint8_t access_size;
    uint64_t address;
} __attribute__((packed));

struct hpet {
    struct ACPISDTheader h;
    uint32_t event_block_id;
    struct generic_address base_address;
    uint16_t clock_tick_unit;
    uint8_t page_oem_flags;
} __attribute__((packed));

typedef struct {
    uint64_t configurationAndCapability;
    uint64_t comparatorValue;
    uint64_t fsbInterruptRoute;
    uint64_t unused;
} __attribute__((packed)) HpetTimer;

typedef struct {
    uint64_t generalCapabilities;
    uint64_t reserved0;
    uint64_t generalConfiguration;
    uint64_t reserved1;
    uint64_t generalIntrruptStatus;
    uint8_t reserved3[0xc8];
    uint64_t mainCounterValue;
    uint64_t reserved4;
    HpetTimer timers[];
} __attribute__((packed)) volatile HpetInfo;

typedef struct dsdt_table {
    uint8_t signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t oem_tableid[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint8_t definition_block;
} __attribute__((packed)) dsdt_table_t;

typedef struct facp_table {
    struct ACPISDTheader h;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t reserved;
    uint8_t preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4bios_req;
    uint8_t pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t pm1_evt_len;
    uint8_t pm1_cnt_len;
    uint8_t pm2_cnt_len;
    uint8_t pm_tmr_len;
    uint8_t gpe0_blk_len;
    uint8_t gpe1_blk_len;
    uint8_t gpe1_base;
    uint8_t cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alrm;
    uint8_t mon_alrm;
    uint8_t century;
    uint16_t iapc_boot_arch;
    uint8_t reserved2;
    uint32_t flags;
    struct generic_address reset_reg;
    uint8_t reset_value;
    uint8_t reserved3[3];
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
    struct generic_address x_pm1a_evt_blk;
    struct generic_address x_pm1b_evt_blk;
    struct generic_address x_pm1a_cnt_blk;
    struct generic_address x_pm1b_cnt_blk;
    struct generic_address x_pm2_cnt_blk;
    struct generic_address x_pm_tmr_blk;
    struct generic_address x_gpe0_blk;
    struct generic_address x_gpe1_blk;
} __attribute__((packed)) acpi_facp_t;

typedef struct {
    struct ACPISDTheader header;
    uint64_t reserved;
} __attribute__((packed)) MCFG;

typedef struct {
    uint64_t base_address;
    uint16_t pci_segment_group;
    uint8_t start_bus;
    uint8_t end_bus;
    uint32_t reserved;
} __attribute__((packed)) MCFG_ENTRY;

typedef struct generic_address GenericAddress;
typedef struct hpet Hpet;
typedef struct madt_header Madtheader;
typedef struct madt_io_apic MadtIOApic;
typedef struct madt_local_apic MadtLocalApic;
typedef struct facp_table acpi_facp_t;

typedef struct madt_int_src_override {
    uint8_t bus_source;
    uint8_t irq_source;
    uint32_t gsi_base;
    uint16_t flags;
} madt_int_src_override_t;

extern uint64_t rsdp_paddr;

void acpi_init();

void *find_table(const char *name);
