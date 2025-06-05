use pci_types::{
    CommandRegister, ConfigRegionAccess, EndpointHeader, PciAddress, PciHeader,
    capability::PciCapability,
};

use crate::rust::bindings::bindings::{
    get_mmio_address, pci_device_t, segment_bus_device_functon_to_pci_address,
};

pub struct PciAccess;

impl ConfigRegionAccess for PciAccess {
    unsafe fn read(&self, address: PciAddress, offset: u16) -> u32 {
        let pci_address = segment_bus_device_functon_to_pci_address(
            address.segment(),
            address.bus(),
            address.device(),
            address.function(),
        );
        let addr = get_mmio_address(pci_address, offset);
        core::ptr::read_volatile(addr as *const _)
    }

    unsafe fn write(&self, address: PciAddress, offset: u16, value: u32) {
        let pci_address = segment_bus_device_functon_to_pci_address(
            address.segment(),
            address.bus(),
            address.device(),
            address.function(),
        );
        let addr = get_mmio_address(pci_address, offset);
        core::ptr::write_volatile(addr as *mut _, value);
    }
}

#[unsafe(no_mangle)]
extern "C" fn pci_device_init(pci_device: *const pci_device_t) {
    let pci_device = unsafe { &*pci_device };
    let pci_address = PciAddress::new(
        pci_device.segment,
        pci_device.bus,
        pci_device.slot,
        pci_device.func,
    );

    let header = PciHeader::new(pci_address);
    if let Some(mut endpoint) = EndpointHeader::from_header(header, PciAccess) {
        endpoint.update_command(PciAccess, |command| {
            command
                | CommandRegister::BUS_MASTER_ENABLE
                | CommandRegister::IO_ENABLE
                | CommandRegister::MEMORY_ENABLE
        });

        endpoint
            .capabilities(PciAccess)
            .for_each(|capability| match capability {
                PciCapability::Msi(msi) => {
                    msi.set_enabled(true, PciAccess);
                }
                PciCapability::MsiX(mut msix) => {
                    msix.set_enabled(true, PciAccess);
                }
                _ => {}
            });
    }
}
