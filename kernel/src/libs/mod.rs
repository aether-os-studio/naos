use core::fmt;
use core::fmt::Write;
use spin::Mutex;

use crate::rust::bindings::bindings::printk;

pub struct KernelWriter;

pub static WRITER: Mutex<KernelWriter> = Mutex::new(KernelWriter);

impl Write for KernelWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        unsafe {
            printk(b"%s\0".as_ptr() as *const _, s.as_ptr());
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
