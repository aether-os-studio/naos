// Copyright (C) 2025-2026  lihanrui2913
#include "e1000.h"
#include <libs/aether/mm.h>
#include <libs/aether/pci.h>
#include <libs/aether/net.h>
#include <libs/klibc.h>
#include <net/rtnl.h>

// Global device array
e1000_device_t *e1000_devices[MAX_E1000_DEVICES];
int e1000_device_count = 0;

// MMIO Read/Write functions
static inline uint32_t e1000_read32(e1000_device_t *dev, uint32_t reg) {
    return *((volatile uint32_t *)(dev->mmio_base + reg));
}

static inline void e1000_write32(e1000_device_t *dev, uint32_t reg,
                                 uint32_t value) {
    *((volatile uint32_t *)(dev->mmio_base + reg)) = value;
}

// Read from EEPROM
static int e1000_read_eeprom(e1000_device_t *dev, uint16_t offset,
                             uint16_t *data) {
    e1000_write32(dev, E1000_EERD,
                  (offset << E1000_EERD_ADDR_SHIFT) | E1000_EERD_START);

    for (int i = 0; i < 1000; i++) {
        uint32_t val = e1000_read32(dev, E1000_EERD);
        if (val & E1000_EERD_DONE) {
            *data = (val >> E1000_EERD_DATA_SHIFT) & 0xFFFF;
            return 0;
        }
    }
    return -1;
}

// Get MAC address from EEPROM or registers
static int e1000_get_mac_address(e1000_device_t *dev) {
    uint16_t data;

    // Try to read from EEPROM first
    if (e1000_read_eeprom(dev, 0, &data) == 0) {
        dev->mac[0] = data & 0xFF;
        dev->mac[1] = (data >> 8) & 0xFF;

        if (e1000_read_eeprom(dev, 1, &data) == 0) {
            dev->mac[2] = data & 0xFF;
            dev->mac[3] = (data >> 8) & 0xFF;

            if (e1000_read_eeprom(dev, 2, &data) == 0) {
                dev->mac[4] = data & 0xFF;
                dev->mac[5] = (data >> 8) & 0xFF;
                return 0;
            }
        }
    }

    // Fallback to reading from RAL/RAH registers
    uint32_t ral = e1000_read32(dev, E1000_RA);
    uint32_t rah = e1000_read32(dev, E1000_RA + 4);

    dev->mac[0] = ral & 0xFF;
    dev->mac[1] = (ral >> 8) & 0xFF;
    dev->mac[2] = (ral >> 16) & 0xFF;
    dev->mac[3] = (ral >> 24) & 0xFF;
    dev->mac[4] = rah & 0xFF;
    dev->mac[5] = (rah >> 8) & 0xFF;

    return 0;
}

// Initialize RX descriptors and buffers
static int e1000_init_rx(e1000_device_t *dev) {
    // Allocate RX descriptors (must be 16-byte aligned)
    dev->rx_descs = (struct e1000_rx_desc *)alloc_frames_bytes(
        E1000_NUM_RX_DESC * sizeof(struct e1000_rx_desc) + 15);
    if (!dev->rx_descs) {
        return -1;
    }

    // Align to 16-byte boundary
    dev->rx_descs =
        (struct e1000_rx_desc *)(((uintptr_t)dev->rx_descs + 15) & ~15);

    // Initialize RX descriptors and buffers
    for (int i = 0; i < E1000_NUM_RX_DESC; i++) {
        dev->rx_buffers[i] = alloc_frames_bytes(E1000_RX_BUFFER_SIZE);
        if (!dev->rx_buffers[i]) {
            return -1;
        }

        dev->rx_descs[i].buffer_addr =
            (uint64_t)virt_to_phys(dev->rx_buffers[i]);
        dev->rx_descs[i].status = 0;
        dev->rx_descs[i].errors = 0;
        dev->rx_descs[i].length = 0;
    }

    // Program RX descriptor registers
    uint64_t rx_desc_phys = (uint64_t)virt_to_phys(dev->rx_descs);
    e1000_write32(dev, E1000_RDBAL, rx_desc_phys & 0xFFFFFFFF);
    e1000_write32(dev, E1000_RDBAH, rx_desc_phys >> 32);
    e1000_write32(dev, E1000_RDLEN,
                  E1000_NUM_RX_DESC * sizeof(struct e1000_rx_desc));
    e1000_write32(dev, E1000_RDH, 0);
    e1000_write32(dev, E1000_RDT, E1000_NUM_RX_DESC - 1);
    dev->rx_tail = E1000_NUM_RX_DESC - 1;

    // Configure RX control
    uint32_t rctl = e1000_read32(dev, E1000_RCTL);
    rctl |= E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SECRC | E1000_RCTL_LPE;
    e1000_write32(dev, E1000_RCTL, rctl);

    return 0;
}

// Initialize TX descriptors and buffers
static int e1000_init_tx(e1000_device_t *dev) {
    // Allocate TX descriptors (must be 16-byte aligned)
    dev->tx_descs = (struct e1000_tx_desc *)alloc_frames_bytes(
        E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc) + 15);
    if (!dev->tx_descs) {
        return -1;
    }

    // Align to 16-byte boundary
    dev->tx_descs =
        (struct e1000_tx_desc *)(((uintptr_t)dev->tx_descs + 15) & ~15);

    // Initialize TX descriptors
    memset(dev->tx_descs, 0, E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc));
    for (int i = 0; i < E1000_NUM_TX_DESC; i++) {
        dev->tx_buffers[i] = NULL;
    }

    // Program TX descriptor registers
    uint64_t tx_desc_phys = (uint64_t)virt_to_phys(dev->tx_descs);
    e1000_write32(dev, E1000_TDBAL, tx_desc_phys & 0xFFFFFFFF);
    e1000_write32(dev, E1000_TDBAH, tx_desc_phys >> 32);
    e1000_write32(dev, E1000_TDLEN,
                  E1000_NUM_TX_DESC * sizeof(struct e1000_tx_desc));
    e1000_write32(dev, E1000_TDH, 0);
    e1000_write32(dev, E1000_TDT, 0);
    dev->tx_head = 0;
    dev->tx_tail = 0;

    // Configure TX control
    uint32_t tctl = e1000_read32(dev, E1000_TCTL);
    tctl |= E1000_TCTL_EN | E1000_TCTL_PSP;
    tctl |= (0x10 << E1000_TCTL_CT_SHIFT) | (0x40 << E1000_TCTL_COLD_SHIFT);
    e1000_write32(dev, E1000_TCTL, tctl);

    // Configure TX IPG
    e1000_write32(dev, E1000_TIPG, 0x0060200A);

    return 0;
}

// Reset the E1000 device
static void e1000_reset(e1000_device_t *dev) {
    // Set reset bit
    uint32_t ctrl = e1000_read32(dev, E1000_CTRL);
    e1000_write32(dev, E1000_CTRL, ctrl | E1000_CTRL_RST);

    // Wait for reset to complete
    for (int i = 0; i < 1000; i++) {
        if (!(e1000_read32(dev, E1000_CTRL) & E1000_CTRL_RST)) {
            break;
        }
    }
}

// Initialize E1000 device
int e1000_init(void *mmio_base) {
    e1000_device_t *dev = (e1000_device_t *)malloc(sizeof(e1000_device_t));
    if (!dev) {
        printk("e1000: Failed to allocate device structure\n");
        return -1;
    }

    memset(dev, 0, sizeof(e1000_device_t));
    dev->mmio_base = mmio_base;
    dev->mtu = E1000_MTU;

    // Reset device
    e1000_reset(dev);

    // Get MAC address
    if (e1000_get_mac_address(dev) != 0) {
        printk("e1000: Failed to get MAC address\n");
        free(dev);
        return -1;
    }

    printk("e1000: MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", dev->mac[0],
           dev->mac[1], dev->mac[2], dev->mac[3], dev->mac[4], dev->mac[5]);

    // Initialize RX and TX
    if (e1000_init_rx(dev) != 0) {
        printk("e1000: Failed to initialize RX\n");
        free(dev);
        return -1;
    }

    if (e1000_init_tx(dev) != 0) {
        printk("e1000: Failed to initialize TX\n");
        free(dev);
        return -1;
    }

    // Disable interrupts (polling mode)
    e1000_write32(dev, E1000_IMC, 0xFFFFFFFF);

    // Store device and register with network framework
    e1000_devices[e1000_device_count++] = dev;
    regist_netdev(dev, dev->mac, dev->mtu, e1000_send, e1000_receive);

    struct net_device *rtnl_dev = rtnl_dev_alloc("e1000", ARPHRD_ETHER);

    memcpy(rtnl_dev->addr, dev->mac, 6);
    rtnl_dev->addr_len = 6;

    memset(rtnl_dev->broadcast, 0xFF, 6);

    rtnl_dev->mtu = dev->mtu;

    rtnl_dev_register(rtnl_dev);

    rtnl_notify_link(rtnl_dev, RTM_NEWLINK);

    return 0;
}

// Send packet (polling mode)
int e1000_send(void *dev_desc, void *data, uint32_t len) {
    e1000_device_t *dev = (e1000_device_t *)dev_desc;

    if (len > E1000_MTU || len == 0) {
        return -1;
    }

    // Check if we have a free TX descriptor
    uint16_t next_tail = (dev->tx_tail + 1) % E1000_NUM_TX_DESC;
    if (next_tail == dev->tx_head) {
        // TX queue full
        return -1;
    }

    // Allocate buffer for packet
    void *tx_buffer = alloc_frames_bytes(len);
    if (!tx_buffer) {
        return -1;
    }

    // Copy data to buffer
    memcpy(tx_buffer, data, len);

    // Setup TX descriptor
    dev->tx_descs[dev->tx_tail].buffer_addr = (uint64_t)virt_to_phys(tx_buffer);
    dev->tx_descs[dev->tx_tail].length = len;
    dev->tx_descs[dev->tx_tail].cmd =
        E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS;
    dev->tx_descs[dev->tx_tail].status = 0;

    // Store buffer pointer for later cleanup
    dev->tx_buffers[dev->tx_tail] = tx_buffer;

    // Update tail pointer
    dev->tx_tail = next_tail;
    e1000_write32(dev, E1000_TDT, dev->tx_tail);

    // Poll for completion
    while (!(dev->tx_descs[dev->tx_head].status & E1000_TXD_STAT_DD)) {
        // Wait for transmission to complete
    }

    // Clean up completed descriptors
    while (dev->tx_head != dev->tx_tail) {
        if (dev->tx_descs[dev->tx_head].status & E1000_TXD_STAT_DD) {
            if (dev->tx_buffers[dev->tx_head]) {
                free_frames_bytes(dev->tx_buffers[dev->tx_head], len);
                dev->tx_buffers[dev->tx_head] = NULL;
            }
            dev->tx_descs[dev->tx_head].status = 0;
            dev->tx_head = (dev->tx_head + 1) % E1000_NUM_TX_DESC;
        } else {
            break;
        }
    }

    return len;
}

// Receive packet (polling mode)
int e1000_receive(void *dev_desc, void *buffer, uint32_t buffer_size) {
    e1000_device_t *dev = (e1000_device_t *)dev_desc;

    uint16_t next_rx = (dev->rx_tail + 1) % E1000_NUM_RX_DESC;
    struct e1000_rx_desc *desc = &dev->rx_descs[next_rx];

    bool have_data = !!(desc->status & E1000_RXD_STAT_DD);

    if (!have_data) {
        // No packet available
        return 0;
    }

    if (desc->errors &
        (E1000_RXD_ERR_CE | E1000_RXD_ERR_SE | E1000_RXD_ERR_SEQ |
         E1000_RXD_ERR_CXE | E1000_RXD_ERR_RXE)) {
        // Packet has errors, discard it
        goto cleanup;
    }

    uint32_t packet_len = desc->length;
    if (packet_len > buffer_size) {
        packet_len = buffer_size;
    }

    // Copy packet data to user buffer
    memcpy(buffer, phys_to_virt((void *)desc->buffer_addr), packet_len);

cleanup:
    // Recycle the descriptor
    desc->status = 0;
    dev->rx_tail = next_rx;
    e1000_write32(dev, E1000_RDT, dev->rx_tail);

    return have_data ? packet_len : 0;
}

// Check if packets are available
bool e1000_has_packets(void *dev_desc) {
    e1000_device_t *dev = (e1000_device_t *)dev_desc;
    uint16_t next_rx = (dev->rx_tail + 1) % E1000_NUM_RX_DESC;
    return (dev->rx_descs[next_rx].status & E1000_RXD_STAT_DD) != 0;
}

// Poll for received packets (can be called periodically)
void e1000_poll(void *dev_desc) {
    // This function can be implemented if needed for background polling
    // Currently, packets are checked on-demand in e1000_receive
}

// Get device by index (similar to virtio-net interface)
e1000_device_t *e1000_get_device(uint32_t index) {
    if (index >= e1000_device_count) {
        return NULL;
    }
    return e1000_devices[index];
}

// Get device count (similar to virtio-net interface)
uint32_t e1000_get_device_count(void) { return e1000_device_count; }

// PCI Driver Interface
static int e1000_pci_probe(pci_device_t *pci_dev, uint32_t vendor_device_id) {
    if (pci_dev->device_id != 0x100e && pci_dev->device_id != 0x100f) {
        return 0;
    }

    printk("e1000: Found Intel E1000 network controller\n");

    // Find MMIO BAR
    uint64_t mmio_base = 0;
    uint64_t mmio_size = 0;
    for (int i = 0; i < 6; i++) {
        if (pci_dev->bars[i].size > 0 && pci_dev->bars[i].mmio) {
            mmio_base = pci_dev->bars[i].address;
            mmio_size = pci_dev->bars[i].size;
            break;
        }
    }

    if (mmio_base == 0) {
        printk("e1000: No MMIO BAR found\n");
        return -1;
    }

    // Map MMIO region
    void *mmio_vaddr = (void *)phys_to_virt(mmio_base);
    map_page_range(get_current_page_dir(false), (uint64_t)mmio_vaddr, mmio_base,
                   mmio_size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE);

    // Initialize E1000 device
    return e1000_init(mmio_vaddr);
}

static void e1000_pci_remove(pci_device_t *pci_dev) {
    // Find and remove the device
    for (int i = 0; i < e1000_device_count; i++) {
        e1000_device_t *dev = e1000_devices[i];
        // Compare MMIO base to identify the device
        if ((uint64_t)dev->mmio_base >= pci_dev->bars[0].address &&
            (uint64_t)dev->mmio_base <
                pci_dev->bars[0].address + pci_dev->bars[0].size) {
            // Disable device
            e1000_write32(dev, E1000_RCTL, 0);
            e1000_write32(dev, E1000_TCTL, 0);

            // Free buffers
            for (int j = 0; j < E1000_NUM_RX_DESC; j++) {
                if (dev->rx_buffers[j]) {
                    free_frames_bytes(dev->rx_buffers[j], E1000_RX_BUFFER_SIZE);
                }
            }
            for (int j = 0; j < E1000_NUM_TX_DESC; j++) {
                if (dev->tx_buffers[j]) {
                    free_frames_bytes(dev->tx_buffers[j], E1000_TX_BUFFER_SIZE);
                }
            }

            // Free descriptors
            if (dev->rx_descs) {
                free_frames_bytes(dev->rx_descs,
                                  E1000_NUM_RX_DESC *
                                      sizeof(struct e1000_rx_desc));
            }
            if (dev->tx_descs) {
                free_frames_bytes(dev->tx_descs,
                                  E1000_NUM_TX_DESC *
                                      sizeof(struct e1000_tx_desc));
            }

            // Remove from device array
            free(dev);
            e1000_devices[i] = NULL;

            // Shift remaining devices
            for (int j = i; j < e1000_device_count - 1; j++) {
                e1000_devices[j] = e1000_devices[j + 1];
            }
            e1000_device_count--;
            break;
        }
    }
}

static void e1000_pci_shutdown(pci_device_t *pci_dev) {
    e1000_pci_remove(pci_dev);
}

// PCI Driver Structure
static pci_driver_t e1000_driver = {
    .name = "e1000",
    .class_id = 0x00020000,         // Network controller class
    .vendor_device_id = 0x80860000, // Intel vendor ID + E1000 device ID
    .probe = e1000_pci_probe,
    .remove = e1000_pci_remove,
    .shutdown = e1000_pci_shutdown,
    .flags = 0,
};

// Module initialization function
int dlmain(void) {
    regist_pci_driver(&e1000_driver);
    return 0;
}
