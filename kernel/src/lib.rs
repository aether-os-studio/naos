#![no_std]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]
#![allow(unused_variables)]

pub mod arch;
pub mod libs;
pub mod mm;
pub mod rust;

#[unsafe(no_mangle)]
extern "C" fn rust_init() {
    println!("rust initialized");
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    loop {}
}
