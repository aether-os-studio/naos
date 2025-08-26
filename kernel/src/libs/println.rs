use core::{ffi::CStr, fmt::Write};

use alloc::vec;

use crate::rust::bindings::bindings::{flanterm_write, ft_ctx, serial_printk};

pub struct KernelWriter;

impl Write for KernelWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe {
            serial_printk(
                s.as_ptr() as usize as *mut core::ffi::c_char,
                s.len() as core::ffi::c_int,
            );
            flanterm_write(
                ft_ctx,
                s.as_ptr() as usize as *mut core::ffi::c_char,
                s.len(),
            );
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
