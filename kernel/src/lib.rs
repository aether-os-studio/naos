#![no_std]
#![feature(allocator_api)]
#![feature(vec_into_raw_parts)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use core::hint::spin_loop;

use crate::rust::bindings::bindings::task_exit;

extern crate alloc;

pub mod arch;
pub mod drivers;
pub mod fs;
pub mod ipc;
pub mod libs;
pub mod mm;
pub mod rust;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("{}", info);
    unsafe { task_exit(-1) };
    loop {
        spin_loop();
    }
}
