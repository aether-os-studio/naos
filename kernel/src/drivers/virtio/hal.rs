use core::ptr::NonNull;

use virtio_drivers::Hal;

use crate::{
    mm::phys_to_virt,
    rust::bindings::bindings::{
        DEFAULT_PAGE_SIZE, PT_FLAG_R, PT_FLAG_W, alloc_frames, free_frames, get_current_page_dir,
        map_page_range, translate_address,
    },
};

pub struct HalImpl;

unsafe impl Hal for HalImpl {
    fn dma_alloc(
        pages: usize,
        direction: virtio_drivers::BufferDirection,
    ) -> (virtio_drivers::PhysAddr, core::ptr::NonNull<u8>) {
        let phys = unsafe { alloc_frames(pages) as usize };
        let virt = phys_to_virt(phys);
        return (phys, unsafe { NonNull::new_unchecked(virt as *mut u8) });
    }

    unsafe fn dma_dealloc(
        paddr: virtio_drivers::PhysAddr,
        vaddr: core::ptr::NonNull<u8>,
        pages: usize,
    ) -> i32 {
        free_frames(paddr as u64, pages as u64);
        0
    }

    unsafe fn mmio_phys_to_virt(
        paddr: virtio_drivers::PhysAddr,
        size: usize,
    ) -> core::ptr::NonNull<u8> {
        let virt = phys_to_virt(paddr);
        map_page_range(
            get_current_page_dir(false),
            virt as u64,
            paddr as u64,
            ((size + DEFAULT_PAGE_SIZE as usize - 1) / DEFAULT_PAGE_SIZE as usize) as u64,
            PT_FLAG_R as u64 | PT_FLAG_W as u64,
        );
        NonNull::new_unchecked(virt as *mut u8)
    }

    unsafe fn share(
        buffer: core::ptr::NonNull<[u8]>,
        _direction: virtio_drivers::BufferDirection,
    ) -> virtio_drivers::PhysAddr {
        translate_address(
            get_current_page_dir(false),
            buffer.as_ptr() as *mut u8 as u64,
        ) as virtio_drivers::PhysAddr
    }

    unsafe fn unshare(
        _paddr: virtio_drivers::PhysAddr,
        _buffer: core::ptr::NonNull<[u8]>,
        _direction: virtio_drivers::BufferDirection,
    ) {
    }
}
