#pragma once

#include <libs/klibc.h>
#include <arch/arch.h>

uint64_t get_rsdp_paddr();

int acpi_eval_dsm_for_pci(uint16_t segment, uint8_t bus, uint8_t slot,
                          uint8_t func, const uint8_t guid[16],
                          uint32_t revision, bool use_nvpcf_scope,
                          uint32_t sub_function, const void *arg3,
                          uint16_t arg3_size, bool arg3_is_integer,
                          uint32_t *out_status, void *out_data,
                          uint32_t *inout_size);
