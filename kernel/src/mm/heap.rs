use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use good_memory_allocator::SpinLockedAllocator;
use spin::Mutex;

pub const KERNEL_HEAP_SIZE: usize = 128 * 1024 * 1024;

use crate::{
    mm::phys_to_virt,
    rust::bindings::bindings::{
        DEFAULT_PAGE_SIZE, PT_FLAG_R, PT_FLAG_W, alloc_frames, arch_disable_interrupt,
        arch_enable_interrupt, get_current_page_dir, map_page_range,
    },
};

#[global_allocator]
static KERNEL_ALLOCATOR: SpinLockedAllocator = SpinLockedAllocator::empty();

static C_ALLOCATION_MAP: Mutex<BTreeMap<usize, (usize, usize, usize)>> =
    Mutex::new(BTreeMap::new());

fn do_malloc(size: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    let irq = x86_64::instructions::interrupts::are_enabled();
    #[cfg(target_arch = "aarch64")]
    let irq = aarch64::regs::DAIF::I.is_set(1);
    #[cfg(target_arch = "loongarch64")]
    let irq = loongArch64::register::crmd::Crmd::from(loongArch64::register::crmd::read()).ie();

    unsafe { arch_disable_interrupt() };

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
                "do_malloc: vaddr {:#x?} already exists in C Allocation Map, query size: {size}",
                vaddr
            );
        }

        guard.insert(vaddr, (vaddr, len, cap));
        drop(guard);
        unsafe { core::slice::from_raw_parts_mut(vaddr as *mut u8, size) }.fill(0);

        if irq {
            unsafe { arch_enable_interrupt() };
        }

        return vaddr;
    } else {
        if irq {
            unsafe { arch_enable_interrupt() };
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
    #[cfg(target_arch = "aarch64")]
    let irq = aarch64::regs::DAIF::I.is_set(1);
    #[cfg(target_arch = "loongarch64")]
    let irq = loongArch64::register::crmd::Crmd::from(loongArch64::register::crmd::read()).ie();

    arch_disable_interrupt();

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

    if irq {
        use crate::rust::bindings::bindings::arch_enable_interrupt;

        arch_enable_interrupt();
    }

    new_ptr as usize
}

#[unsafe(no_mangle)]
unsafe extern "C" fn free(ptr: *const core::ffi::c_void) {
    #[cfg(target_arch = "x86_64")]
    let irq = x86_64::instructions::interrupts::are_enabled();
    #[cfg(target_arch = "aarch64")]
    let irq = aarch64::regs::DAIF::I.is_set(1);
    #[cfg(target_arch = "loongarch64")]
    let irq = loongArch64::register::crmd::Crmd::from(loongArch64::register::crmd::read()).ie();

    let vaddr = ptr as usize;
    let mut guard = C_ALLOCATION_MAP.lock();
    let p = guard.remove(&vaddr);
    drop(guard);

    if p.is_none() {
        return;
    }
    let (vaddr, len, cap) = p.unwrap();
    drop(Vec::from_raw_parts(vaddr as *mut u8, len, cap));

    if irq {
        use crate::rust::bindings::bindings::arch_enable_interrupt;

        arch_enable_interrupt();
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn heap_init() {
    // map_page_range(
    //     get_current_page_dir(false),
    //     KERNEL_HEAP_START as u64,
    //     0,
    //     KERNEL_HEAP_SIZE as u64,
    //     PT_FLAG_R as u64 | PT_FLAG_W as u64,
    // );

    let heap_start =
        phys_to_virt(alloc_frames(KERNEL_HEAP_SIZE / DEFAULT_PAGE_SIZE as usize) as usize);

    unsafe {
        core::slice::from_raw_parts_mut(heap_start as *mut u64, KERNEL_HEAP_SIZE / size_of::<u64>())
    }
    .fill(0);

    KERNEL_ALLOCATOR.init(heap_start, KERNEL_HEAP_SIZE);
}
