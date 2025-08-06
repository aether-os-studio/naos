#include <libs/aether/pci.h>
#include <mod/dlinker.h>

pci_driver_t *pci_drivers[MAX_PCI_DRIVERS] = {NULL};

int regist_pci_driver(pci_driver_t *driver)
{
    for (int i = 0; i < MAX_PCI_DRIVERS; i++)
    {
        if (!pci_drivers[i])
        {
            pci_drivers[i] = driver;
            break;
        }
    }

    return 0;
}

EXPORT_SYMBOL(regist_pci_driver);
