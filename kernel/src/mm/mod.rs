use crate::rust::bindings::bindings::get_physical_memory_offset;

pub mod heap;

pub fn phys_to_virt(paddr: usize) -> usize {
    paddr + unsafe { get_physical_memory_offset() } as usize
}

pub fn virt_to_phys(vaddr: usize) -> usize {
    vaddr - unsafe { get_physical_memory_offset() } as usize
}
