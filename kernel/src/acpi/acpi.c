#include <libs/klibc.h>
#include <drivers/kernel_logger.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>
#include <arch/arch.h>

bool acpi_initialized = false;

void acpi_init() {
    uacpi_status ret = uacpi_initialize(0);
    if (uacpi_unlikely_error(ret)) {
        return;
    }
    acpi_initialized = true;
}

void acpi_init_after_pci() {
    if (acpi_initialized) {
        /*
         * Load the AML namespace. This feeds DSDT and all SSDTs to the
         * interpreter for execution.
         */
        uacpi_status ret = uacpi_namespace_load();
        if (uacpi_unlikely_error(ret)) {
            printk("uacpi_namespace_load error: %s",
                   uacpi_status_to_string(ret));
            acpi_initialized = false;
            return;
        }

#if defined(__x86_64__)
        // set the interrupt model
        uacpi_set_interrupt_model(UACPI_INTERRUPT_MODEL_IOAPIC);
#endif

        /*
         * Initialize the namespace. This calls all necessary _STA/_INI AML
         * methods, as well as _REG for registered operation region handlers.
         */
        ret = uacpi_namespace_initialize();
        if (uacpi_unlikely_error(ret)) {
            printk("uacpi_namespace_initialize error: %s",
                   uacpi_status_to_string(ret));
            acpi_initialized = false;
            return;
        }
    }
}
