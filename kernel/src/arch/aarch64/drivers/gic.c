#include <arch/aarch64/drivers/gic.h>

irq_controller_t gic_controller = {
    .install = NULL,
    .mask = NULL,
    .unmask = gic_enable_interrupt,
    .ack = gic_send_eoi,
};
