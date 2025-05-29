#![no_std]
#![feature(allocator_api)]
#![feature(vec_into_raw_parts)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate alloc;

pub mod arch;
pub mod drivers;
pub mod fs;
pub mod ipc;
pub mod libs;
pub mod mm;
pub mod rust;

#[unsafe(no_mangle)]
extern "C" fn rust_init() {
    println!("rust initialized");
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}
