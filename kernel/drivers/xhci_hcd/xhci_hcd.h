#pragma once

#include <libs/aether/stdio.h>
#include <libs/aether/mm.h>
#include <libs/aether/pci.h>

int xhci_probe(pci_device_t *dev, uint32_t vendor_device_id);

void xhci_remove(pci_device_t *dev);
void xhci_shutdown(pci_device_t *dev);
