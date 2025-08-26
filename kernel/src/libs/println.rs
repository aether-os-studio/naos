use core::{ffi::CStr, fmt::Write};

use alloc::vec::Vec;

use crate::rust::bindings::bindings::printk;

pub struct KernelWriter;

impl Write for KernelWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let mut buffer = s.as_bytes().to_vec();
        buffer.push(0);

        let cstr = unsafe { CStr::from_bytes_with_nul_unchecked(buffer.as_slice()) };

        unsafe {
            printk(cstr.as_ptr());
        }

        Ok(())
    }
}

pub fn _print(args: core::fmt::Arguments) {
    let _ = KernelWriter.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => (
        $crate::libs::println::_print(format_args!($($arg)*))
    )
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)))
}
