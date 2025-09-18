#pragma once

/**
 * @brief 生成架构相关的msi的message address
 *
 */
#define ia64_pci_get_arch_msi_message_address(processor)                       \
    (0xfee00000UL | ((uint8_t)processor << 12))

/**
 * @brief 生成架构相关的message data
 *
 */
#define ia64_pci_get_arch_msi_message_data(vector, processor, edge_trigger,    \
                                           assert)                             \
    ((uint32_t)((vector & 0xff) | (edge_trigger == 1 ? 0 : (1 << 15)) |        \
                ((assert == 0) ? 0 : (1 << 14))))
