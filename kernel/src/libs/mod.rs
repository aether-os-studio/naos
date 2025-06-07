use alloc::string::ToString;
use core::fmt;
use core::fmt::Write;
use spin::Mutex;

pub mod dma;
pub mod io;

use crate::rust::bindings::bindings::printk;

pub struct KernelWriter;

pub static WRITER: Mutex<KernelWriter> = Mutex::new(KernelWriter);

impl Write for KernelWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut string = s.to_string();
        string.push('\0');
        unsafe {
            printk(string.as_ptr() as *const _);
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::libs::WRITER.lock(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
