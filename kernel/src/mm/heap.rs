use core::alloc::GlobalAlloc;

use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use spin::Mutex;

use crate::rust::bindings::bindings::{free, memalign};

pub struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        memalign(layout.align() as u64, layout.size() as u64) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        free(ptr as *mut core::ffi::c_void);
    }
}

#[global_allocator]
pub static KERNEL_ALLOCATOR: Allocator = Allocator;
