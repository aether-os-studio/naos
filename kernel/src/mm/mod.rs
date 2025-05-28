use core::alloc::GlobalAlloc;

use crate::rust::bindings::bindings::{aligned_alloc, free};

pub struct HeapAllocator;

unsafe impl GlobalAlloc for HeapAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        aligned_alloc(layout.align() as u64, layout.size() as u64) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        free(ptr as _);
    }
}

pub static KERNEL_ALLOCATOR: HeapAllocator = HeapAllocator;
