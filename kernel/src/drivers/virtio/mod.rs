use hal::HalImpl;
use virtio_drivers::{
    device,
    transport::{
        DeviceType, Transport,
        pci::{
            PciTransport,
            bus::{ConfigurationAccess, DeviceFunction, PciRoot},
        },
    },
};

use crate::{
    println,
    rust::bindings::bindings::{
        get_mmio_address, pci_device_t, pci_find_vid, segment_bus_device_functon_to_pci_address,
    },
};

pub mod decode;
pub mod hal;
pub mod input;

#[derive(Clone)]
pub struct PciConfigurationAccess;

impl ConfigurationAccess for PciConfigurationAccess {
    fn read_word(
        &self,
        device_function: virtio_drivers::transport::pci::bus::DeviceFunction,
        register_offset: u8,
    ) -> u32 {
        unsafe {
            let pci_address = segment_bus_device_functon_to_pci_address(
                device_function.segment,
                device_function.bus,
                device_function.device,
                device_function.function,
            );
            (get_mmio_address(pci_address, register_offset as u16) as *const u32).read()
        }
    }

    fn write_word(
        &mut self,
        device_function: virtio_drivers::transport::pci::bus::DeviceFunction,
        register_offset: u8,
        data: u32,
    ) {
        unsafe {
            let pci_address = segment_bus_device_functon_to_pci_address(
                device_function.segment,
                device_function.bus,
                device_function.device,
                device_function.function,
            );
            (get_mmio_address(pci_address, register_offset as u16) as *mut u32).write(data)
        };
    }

    unsafe fn unsafe_clone(&self) -> Self {
        self.clone()
    }
}

#[unsafe(no_mangle)]
extern "C" fn virtio_init() {
    let virtio_devices: &mut [*mut pci_device_t; 8] = &mut [
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    ];

    let mut virtio_device_num: u32 = 0;

    unsafe {
        pci_find_vid(
            virtio_devices as *mut *mut pci_device_t,
            &mut virtio_device_num as *mut u32,
            0x1AF4,
        );

        for i in 0..virtio_device_num as usize {
            let pci_device = *virtio_devices[i];
            let op = *pci_device.op;
            let mut value = op.read.unwrap()(
                pci_device.bus as u32,
                pci_device.slot as u32,
                pci_device.func as u32,
                pci_device.segment as u32,
                0x04,
            );
            value |= 0x6;
            op.write.unwrap()(
                pci_device.bus as u32,
                pci_device.slot as u32,
                pci_device.func as u32,
                pci_device.segment as u32,
                0x04,
                value,
            );

            let mut access = PciRoot::new(PciConfigurationAccess);
            let device_function = DeviceFunction {
                segment: pci_device.segment,
                bus: pci_device.bus,
                device: pci_device.slot,
                function: pci_device.func,
            };

            if let Ok(transport) =
                PciTransport::new::<HalImpl, PciConfigurationAccess>(&mut access, device_function)
            {
                match transport.device_type() {
                    DeviceType::Input => input::init_pci(transport),
                    DeviceType::Network => crate::drivers::net::virtio::init_pci(transport),
                    _ => {}
                }
            }
        }
    }
}
