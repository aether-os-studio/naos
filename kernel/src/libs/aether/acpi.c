#include <libs/aether/acpi.h>
#include <boot/boot.h>
#include <mod/dlinker.h>

uint64_t get_rsdp_paddr() { return boot_get_acpi_rsdp(); }

EXPORT_SYMBOL(get_rsdp_paddr);
