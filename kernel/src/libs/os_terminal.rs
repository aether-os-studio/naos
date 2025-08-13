use ::os_terminal::Terminal;
use ::os_terminal::font::{BitmapFont, TrueTypeFont};
use ::os_terminal::{DrawTarget, Rgb};
use alloc::boxed::Box;
use core::ffi::CStr;
use core::fmt::{self, Write};
use core::slice::from_raw_parts_mut;
use spin::{Lazy, Mutex};

use crate::rust::bindings::bindings::framebuffer;

#[derive(Debug, Clone, Copy)]
pub enum PixelFormat {
    Rgb,
    Bgr,
    U8,
    Unknown,
}

pub struct Display {
    width: usize,
    height: usize,
    stride: usize,
    buffer: *mut u32,
    shifts: (u8, u8, u8),
    convert_color: fn((u8, u8, u8), Rgb) -> u32,
}

impl Display {
    pub fn new() -> Self {
        let frame_buffer = unsafe { *framebuffer };

        let red_mask_size = frame_buffer.red_mask_size;
        let green_mask_size = frame_buffer.green_mask_size;
        let blue_mask_size = frame_buffer.blue_mask_size;

        let shifts = (
            frame_buffer.red_mask_shift + (red_mask_size - 8),
            frame_buffer.green_mask_shift + (green_mask_size - 8),
            frame_buffer.blue_mask_shift + (blue_mask_size - 8),
        );

        let convert_color = |shifts: (u8, u8, u8), color: Rgb| {
            ((color.0 as u32) << shifts.0)
                | ((color.1 as u32) << shifts.1)
                | ((color.2 as u32) << shifts.2)
        };

        Self {
            shifts,
            convert_color,
            width: frame_buffer.width as usize,
            height: frame_buffer.height as usize,
            buffer: frame_buffer.address as *mut u32,
            stride: frame_buffer.pitch as usize / size_of::<u32>(),
        }
    }
}

impl DrawTarget for Display {
    fn size(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    #[inline(always)]
    fn draw_pixel(&mut self, x: usize, y: usize, color: Rgb) {
        let color = (self.convert_color)(self.shifts, color);
        unsafe { self.buffer.add(y * self.stride + x).write(color) }
    }
}

unsafe impl Send for Display {}
unsafe impl Sync for Display {}

pub static TERMINAL: Lazy<Mutex<Terminal<Display>>> = Lazy::new(|| {
    let mut terminal = Terminal::new(Display::new());
    terminal.set_font_manager(Box::new(BitmapFont));
    terminal.set_crnl_mapping(true);
    Mutex::new(terminal)
});

pub fn set_font(size: f32, font: &'static [u8]) {
    TERMINAL
        .lock()
        .set_font_manager(Box::new(TrueTypeFont::new(size, font)));
}

#[inline]
pub fn _print(args: fmt::Arguments) {
    TERMINAL.lock().write_fmt(args).unwrap();
}

#[unsafe(no_mangle)]
unsafe extern "C" fn os_terminal_write(buf: *const core::ffi::c_char, len: usize) {
    let buf = core::slice::from_raw_parts(buf as *const u8, len);
    TERMINAL.lock().process(buf);
}
