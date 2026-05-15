#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <libs/klibc.h>
#include <drivers/bus/bus.h>

#define PCI_CONF_VENDOR 0X0   // Vendor ID
#define PCI_CONF_DEVICE 0X2   // Device ID
#define PCI_CONF_COMMAND 0x4  // Command
#define PCI_CONF_STATUS 0x6   // Status
#define PCI_CONF_REVISION 0x8 // revision ID

#define PCI_DEVICE_MAX 2048

#define EXPORT_BYTE(target, first)                                             \
    ((first) ? ((target) & ~0xFF00) : (((target) & ~0x00FF) >> 8))

/**
 * Encode segment/bus/device/function into the implementation-defined address
 * form used by the current PCI host-controller backend.
 */
uint32_t segment_bus_device_functon_to_pci_address(uint16_t segment,
                                                   uint8_t bus, uint8_t device,
                                                   uint8_t function);

#define PCI_BAR_GET_SIZE 1
#define PCI_BAR_GET_IS_MMIO 2

typedef struct {
    uint64_t address;
    uint64_t size;
    bool mmio;
    bool prefetchable;
} pci_bar_t;

/**
 * Low-level PCI configuration-space accessors supplied by a host-controller
 * implementation such as ECAM or architecture-specific glue.
 */
typedef struct {
    uint64_t (*convert_bar_address)(uint64_t bar_address);
    uint64_t (*allocate_bar_address)(uint32_t bus, uint32_t slot, uint32_t func,
                                     uint32_t segment, uint32_t bar_index,
                                     uint64_t size, bool mmio,
                                     bool prefetchable, bool is_64bit);
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

/**
 * Enumerated PCI function plus driver/runtime state discovered during probing.
 */
typedef struct pci_device {
    const char *name;
    bus_device_t *device;
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

/**
 * Search a device's PCI capability list for a capability ID.
 */
uint32_t pci_enumerate_capability_list(pci_device_t *pci_dev,
                                       uint32_t cap_type);

#define PCI_MCFG_MAX_ENTRIES_LEN 1024

uint64_t get_mmio_address(uint32_t pci_address, uint16_t offset);

/**
 * Return a human-readable class string for a PCI class code.
 */
const char *pci_classname(uint32_t classcode);
/**
 * Collect all enumerated devices with the requested vendor ID.
 */
void pci_find_vid(pci_device_t **result, uint32_t *n, uint32_t vid);
/**
 * Collect all enumerated devices with the requested class code.
 */
void pci_find_class(pci_device_t **result, uint32_t *n, uint32_t class_code);
/**
 * Look up a previously enumerated device by bus/device/function/segment.
 */
pci_device_t *pci_find_bdfs(uint8_t bus, uint8_t slot, uint8_t func,
                            uint16_t segment);
/**
 * Enumerate all buses reachable from one PCI segment group.
 */
void pci_scan_segment(pci_device_op_t *op, uint16_t segment_group);
/**
 * Enumerate one PCI bus and the functions reachable beneath it.
 */
void pci_scan_bus(pci_device_op_t *op, uint16_t segment_group, uint8_t bus);
/**
 * Enumerate one concrete PCI function and populate pci_device_t state.
 */
void pci_scan_function(pci_device_op_t *op, uint16_t segment, uint8_t bus,
                       uint8_t device, uint8_t function);
/**
 * Initialize host-controller access before bus enumeration starts.
 */
void pci_controller_init();
/**
 * Enumerate PCI devices and probe registered PCI drivers.
 */
void pci_init();

#define PCI_DRIVER_FLAGS_NEED_SYSFS (1 << 0)

struct pci_driver;
typedef bool (*pci_driver_match_t)(pci_device_t *dev,
                                   const struct pci_driver *driver);

/**
 * High-level PCI driver descriptor. The core matches enumerated pci_device_t
 * objects against this table and then calls probe/remove/shutdown.
 */
typedef struct pci_driver {
    const char *name;
    uint32_t class_id;
    pci_driver_match_t match;
    int (*probe)(pci_device_t *dev);
    void (*remove)(pci_device_t *dev);
    void (*shutdown)(pci_device_t *dev);
    int flags;
    void *private_data;
} pci_driver_t;

#define MAX_PCI_DRIVERS 256

/**
 * Register a PCI driver with the PCI core.
 */
int regist_pci_driver(pci_driver_t *driver);
pci_driver_t *pci_get_current_probe_driver(void);
