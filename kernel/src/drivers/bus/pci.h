#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <libs/klibc.h>

#define PCI_CONF_VENDOR 0X0   // Vendor ID
#define PCI_CONF_DEVICE 0X2   // Device ID
#define PCI_CONF_COMMAND 0x4  // Command
#define PCI_CONF_STATUS 0x6   // Status
#define PCI_CONF_REVISION 0x8 // revision ID

#define PCI_DEVICE_MAX 256

#define EXPORT_BYTE(target, first)                                             \
    ((first) ? ((target) & ~0xFF00) : (((target) & ~0x00FF) >> 8))

uint32_t segment_bus_device_functon_to_pci_address(uint16_t segment,
                                                   uint8_t bus, uint8_t device,
                                                   uint8_t function);
uint32_t pci_read(uint32_t b, uint32_t d, uint32_t f, uint32_t s,
                  uint32_t offset);
void pci_write(uint32_t b, uint32_t d, uint32_t f, uint32_t s, uint32_t offset,
               uint32_t value);

#define PCI_BAR_GET_SIZE 1
#define PCI_BAR_GET_IS_MMIO 2

typedef struct {
    uint64_t address;
    uint64_t size;
    bool mmio;
} pci_bar_t;

typedef struct {
    uint64_t (*convert_bar_address)(uint64_t bar_address);
    uint8_t (*read8)(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4,
                     uint32_t arg5);
    void (*write8)(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4,
                   uint32_t arg5, uint8_t value);
    uint16_t (*read16)(uint32_t arg1, uint32_t arg2, uint32_t arg3,
                       uint32_t arg4, uint32_t arg5);
    void (*write16)(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4,
                    uint32_t arg5, uint16_t value);
    uint32_t (*read32)(uint32_t arg1, uint32_t arg2, uint32_t arg3,
                       uint32_t arg4, uint32_t arg5);
    void (*write32)(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4,
                    uint32_t arg5, uint32_t value);
} pci_device_op_t;

struct pcie_info;

typedef struct {
    const char *name;
    uint32_t class_code;
    uint8_t header_type;

    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsystem_vendor_id;
    uint16_t subsystem_device_id;
    uint8_t revision_id;
    uint16_t segment;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    pci_bar_t bars[6];

    uint32_t capability_point;
    struct pcie_info *pcie;

    uint64_t msix_mmio_vaddr;
    uint64_t msix_mmio_size;
    uint32_t msix_offset;
    uint16_t msix_table_size;

    uint8_t irq_line;
    uint8_t irq_pin;

    pci_device_op_t *op;

    void *desc;
} pci_device_t;

extern pci_device_t *pci_devices[PCI_DEVICE_MAX];
extern uint32_t pci_device_number;

uint32_t pci_enumerate_capability_list(pci_device_t *pci_dev,
                                       uint32_t cap_type);

#define PCI_MCFG_MAX_ENTRIES_LEN 1024

uint64_t get_mmio_address(uint32_t pci_address, uint16_t offset);

const char *pci_classname(uint32_t classcode);
void pci_find_vid(pci_device_t **result, uint32_t *n, uint32_t vid);
void pci_find_class(pci_device_t **result, uint32_t *n, uint32_t class_code);
pci_device_t *pci_find_bdfs(uint8_t bus, uint8_t slot, uint8_t func,
                            uint16_t segment);
void pci_scan_segment(pci_device_op_t *op, uint16_t segment_group);
void pci_scan_bus(pci_device_op_t *op, uint16_t segment_group, uint8_t bus);
void pci_scan_function(pci_device_op_t *op, uint16_t segment, uint8_t bus,
                       uint8_t device, uint8_t function);
void pci_controller_init();
void pci_init();
void pci_init_after_sysfs();
void pci_init_after_mount_root();
