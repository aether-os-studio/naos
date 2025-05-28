use core::ptr::NonNull;

use acpi::{
    AcpiHandler, AcpiTables, PhysicalMapping,
    madt::{GicRedistributorEntry, GiccEntry, GicdEntry, Madt, MadtEntry},
    mcfg::Mcfg,
};
use alloc::boxed::Box;
use limine::request::RsdpRequest;
use spin::Lazy;

use crate::{
    mm::phys_to_virt,
    rust::bindings::bindings::{
        DEFAULT_PAGE_SIZE, MCFG, PT_FLAG_R, PT_FLAG_W, get_current_page_dir, map_page_range,
    },
};

#[used]
#[unsafe(link_section = ".limine_requests")]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

pub struct Acpi {
    pub gicd: Option<GicdEntry>,
    pub gicc: Option<GiccEntry>,
    pub gicr: Option<GicRedistributorEntry>,
}

unsafe extern "C" {
    fn pcie_setup(mcfg: *mut MCFG);
}

pub static ACPI: Lazy<Acpi> = Lazy::new(|| {
    let phys = RSDP_REQUEST.get_response().unwrap().address();
    let acpi_tables = {
        let tables = unsafe { AcpiTables::from_rsdp(AcpiMemHandle, phys) }.unwrap();
        Box::leak(Box::new(tables))
    };

    let madt = acpi_tables.find_table::<Madt>().unwrap();

    let mut gicd: Option<GicdEntry> = None;
    let mut gicc: Option<GiccEntry> = None;
    let mut gicr: Option<GicRedistributorEntry> = None;

    for entry in madt.get().entries() {
        if let MadtEntry::Gicd(entry) = entry {
            gicd = Some(entry.clone());
        } else if let MadtEntry::Gicc(entry) = entry {
            gicc = Some(entry.clone());
        } else if let MadtEntry::GicRedistributor(entry) = entry {
            gicr = Some(entry.clone());
        }
    }

    let mcfg = acpi_tables.find_table::<Mcfg>().unwrap();
    let mcfg = mcfg.virtual_start().as_ptr();

    unsafe {
        pcie_setup(mcfg as *mut MCFG);
    }

    let acpi = Acpi {
        gicd: gicd,
        gicc: gicc,
        gicr: gicr,
    };

    acpi
});

#[derive(Clone)]
pub struct AcpiMemHandle;

impl AcpiHandler for AcpiMemHandle {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        let virtual_start = phys_to_virt(physical_address);

        map_page_range(
            get_current_page_dir(false),
            virtual_start as u64,
            physical_address as u64,
            size as u64,
            PT_FLAG_R as u64 | PT_FLAG_W as u64,
        );

        PhysicalMapping::new(
            physical_address,
            NonNull::new_unchecked(virtual_start as *mut T),
            size,
            (size + DEFAULT_PAGE_SIZE as usize - 1) / DEFAULT_PAGE_SIZE as usize,
            self.clone(),
        )
    }

    fn unmap_physical_region<T>(region: &acpi::PhysicalMapping<Self, T>) {}
}
