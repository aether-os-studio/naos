#![no_std]
#![feature(allocator_api)]
#![feature(ip_from)]
#![feature(vec_into_raw_parts)]
#![allow(static_mut_refs)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use core::hint::spin_loop;

use crate::rust::bindings::bindings::task_exit;

extern crate alloc;

pub mod arch;
pub mod drivers;
pub mod fs;
pub mod libs;
pub mod mm;
pub mod net;
pub mod rust;

pub fn addr_of<T>(x: &T) -> usize {
    x as *const T as usize
}

pub fn ref_to_mut<T>(x: &T) -> &mut T {
    unsafe { &mut *(addr_of(x) as *mut T) }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("{}", info);
    println!("{}", info);

    unsafe { task_exit(-1) };

    loop {
        spin_loop();
    }
}
