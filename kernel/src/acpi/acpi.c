#include <libs/klibc.h>
#include <drivers/kernel_logger.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>
#include <arch/arch.h>

void acpi_init() {
    uacpi_status ret = uacpi_initialize(0);
    if (uacpi_unlikely_error(ret)) {
        printk("uacpi_initialize error: %s", uacpi_status_to_string(ret));
        ASSERT(false);
    }

#if defined(__x86_64__)
    hpet_init();
    apic_init();
#endif

    /*
     * Load the AML namespace. This feeds DSDT and all SSDTs to the interpreter
     * for execution.
     */
    ret = uacpi_namespace_load();
    if (uacpi_unlikely_error(ret)) {
        printk("uacpi_namespace_load error: %s", uacpi_status_to_string(ret));
        ASSERT(false);
    }

    // set the interrupt model
    uacpi_set_interrupt_model(UACPI_INTERRUPT_MODEL_IOAPIC);

    /*
     * Initialize the namespace. This calls all necessary _STA/_INI AML methods,
     * as well as _REG for registered operation region handlers.
     */
    ret = uacpi_namespace_initialize();
    if (uacpi_unlikely_error(ret)) {
        printk("uacpi_namespace_initialize error: %s",
               uacpi_status_to_string(ret));
        ASSERT(false);
    }
}