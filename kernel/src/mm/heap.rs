use core::alloc::GlobalAlloc;

use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use spin::Mutex;

use crate::rust::bindings::bindings::{aligned_alloc, free};

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let ptr = aligned_alloc(layout.align() as u64, layout.size() as u64);
        if ptr.is_null() {
            core::ptr::null_mut()
        } else {
            ptr as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        // Implement deallocation logic here
        free(ptr as *mut core::ffi::c_void);
    }
}

#[global_allocator]
static KERNEL_ALLOCATOR: KernelAllocator = KernelAllocator;
