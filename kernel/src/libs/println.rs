use core::fmt::Write;

use crate::rust::bindings::bindings::printk;

pub struct KernelWriter;

impl Write for KernelWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe {
            printk(s.as_ptr() as *const core::ffi::c_char, s.len() as u64);
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
