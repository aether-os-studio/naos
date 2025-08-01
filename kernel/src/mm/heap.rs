use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use linked_list_allocator::LockedHeap;
use spin::Mutex;

use crate::rust::bindings::bindings::{PT_FLAG_R, PT_FLAG_W, get_current_page_dir, map_page_range};

pub const KERNEL_HEAP_START: usize = 0xffff_c000_0000_0000;
pub const KERNEL_HEAP_SIZE: usize = 256 * 1024 * 1024;

#[global_allocator]
static KERNEL_ALLOCATOR: LockedHeap = LockedHeap::empty();

static C_ALLOCATION_MAP: Mutex<BTreeMap<usize, (usize, usize, usize)>> =
    Mutex::new(BTreeMap::new());

fn do_malloc(size: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    let irq = x86_64::instructions::interrupts::are_enabled();
    #[cfg(target_arch = "x86_64")]
    x86_64::instructions::interrupts::disable();

    let space: Vec<u8> = alloc::vec![0u8; size];

    assert!(space.len() == size);

    let (ptr, len, cap) = space.into_raw_parts();
    if !ptr.is_null() {
        let vaddr = ptr as usize;
        let mut guard = C_ALLOCATION_MAP.lock();
        if guard.contains_key(&vaddr) {
            drop(guard);
            unsafe {
                drop(Vec::from_raw_parts(vaddr as *mut u8, len, cap));
            }
            panic!(
                "do_malloc: vaddr {:?} already exists in C Allocation Map, query size: {size}",
                vaddr
            );
        }

        guard.insert(vaddr, (vaddr, len, cap));
        drop(guard);
        unsafe { core::slice::from_raw_parts_mut(vaddr as *mut u8, size) }.fill(0);

        #[cfg(target_arch = "x86_64")]
        {
            if irq {
                x86_64::instructions::interrupts::enable();
            } else {
                x86_64::instructions::interrupts::disable();
            }
        }

        return vaddr;
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            if irq {
                x86_64::instructions::interrupts::enable();
            } else {
                x86_64::instructions::interrupts::disable();
            }
        }

        return 0;
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn malloc(size: usize) -> usize {
    return do_malloc(size);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn calloc(count: usize, size: usize) -> usize {
    return do_malloc(size * count);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn realloc(old_ptr: *mut core::ffi::c_void, new_size: usize) -> usize {
    if old_ptr.is_null() {
        return malloc(new_size);
    }
    if new_size == 0 {
        free(old_ptr);
        return 0;
    }

    #[cfg(target_arch = "x86_64")]
    let irq = x86_64::instructions::interrupts::are_enabled();
    #[cfg(target_arch = "x86_64")]
    x86_64::instructions::interrupts::disable();

    let vaddr = old_ptr as usize;
    let guard = C_ALLOCATION_MAP.lock();
    let Some(&(old_vaddr, old_len, old_cap)) = guard.get(&vaddr) else {
        panic!("realloc: invalid pointer {:p}", old_ptr);
    };
    drop(guard);

    let new_ptr = do_malloc(new_size) as *mut u8;

    let mut guard = C_ALLOCATION_MAP.lock();

    let copy_size = old_len.min(new_size);
    core::ptr::copy_nonoverlapping(old_vaddr as *const u8, new_ptr, copy_size);

    guard.remove(&vaddr);
    drop(guard);
    drop(Vec::from_raw_parts(old_vaddr as *mut u8, old_len, old_cap));

    #[cfg(target_arch = "x86_64")]
    {
        if irq {
            x86_64::instructions::interrupts::enable();
        } else {
            x86_64::instructions::interrupts::disable();
        }
    }

    new_ptr as usize
}

#[unsafe(no_mangle)]
unsafe extern "C" fn free(ptr: *const core::ffi::c_void) {
    #[cfg(target_arch = "x86_64")]
    let irq = x86_64::instructions::interrupts::are_enabled();
    #[cfg(target_arch = "x86_64")]
    x86_64::instructions::interrupts::disable();

    let vaddr = ptr as usize;
    let mut guard = C_ALLOCATION_MAP.lock();
    let p = guard.remove(&vaddr);
    drop(guard);

    if p.is_none() {
        return;
    }
    let (vaddr, len, cap) = p.unwrap();
    drop(Vec::from_raw_parts(vaddr as *mut u8, len, cap));

    #[cfg(target_arch = "x86_64")]
    {
        if irq {
            x86_64::instructions::interrupts::enable();
        } else {
            x86_64::instructions::interrupts::disable();
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn heap_init() {
    map_page_range(
        get_current_page_dir(false),
        KERNEL_HEAP_START as u64,
        0,
        KERNEL_HEAP_SIZE as u64,
        PT_FLAG_R as u64 | PT_FLAG_W as u64,
    );

    unsafe {
        core::slice::from_raw_parts_mut(
            KERNEL_HEAP_START as *mut u64,
            KERNEL_HEAP_SIZE / size_of::<u64>(),
        )
        .fill(0);
    }

    KERNEL_ALLOCATOR
        .lock()
        .init(KERNEL_HEAP_START as *mut u8, KERNEL_HEAP_SIZE);
}
