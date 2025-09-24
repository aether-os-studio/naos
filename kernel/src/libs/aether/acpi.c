#include <libs/aether/acpi.h>
#include <mod/dlinker.h>

uint64_t get_rsdp_paddr() { return (uint64_t)rsdp_request.response->address; }

EXPORT_SYMBOL(get_rsdp_paddr);
