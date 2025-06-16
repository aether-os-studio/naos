use alloc::boxed::Box;
use core::ffi::CStr;
use core::fmt::{self, Write};
use core::slice::from_raw_parts_mut;
use limine::{request::FramebufferRequest, response::FramebufferResponse};
use os_terminal::Terminal;
use os_terminal::font::{BitmapFont, TrueTypeFont};
use os_terminal::{DrawTarget, Rgb};
use spin::{Lazy, Mutex};

#[used]
#[unsafe(link_section = ".limine_requests")]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();
pub static FRAMEBUFFER_RESPONSE: Lazy<&FramebufferResponse> =
    Lazy::new(|| FRAMEBUFFER_REQUEST.get_response().unwrap());

#[derive(Debug, Clone, Copy)]
pub enum PixelFormat {
    Rgb,
    Bgr,
    U8,
    Unknown,
}

pub struct Display {
    buffer: &'static mut [u8],
    width: usize,
    height: usize,
    stride: usize,
    bytes_per_pixel: usize,
    pixel_format: PixelFormat,
}

impl Display {
    pub fn new() -> Self {
        let frame_buffer = FRAMEBUFFER_RESPONSE.framebuffers().next().take().unwrap();

        let width = frame_buffer.width() as _;
        let height = frame_buffer.height() as _;

        let pixel_format = match (
            frame_buffer.red_mask_shift(),
            frame_buffer.green_mask_shift(),
            frame_buffer.blue_mask_shift(),
        ) {
            (0x00, 0x08, 0x10) => PixelFormat::Rgb,
            (0x10, 0x08, 0x00) => PixelFormat::Bgr,
            (0x00, 0x00, 0x00) => PixelFormat::U8,
            _ => PixelFormat::Unknown,
        };

        let pitch = frame_buffer.pitch() as usize;
        let bpp = frame_buffer.bpp() as usize;
        let stride = (pitch / 4) as _;
        let bytes_per_pixel = (bpp / 8) as _;

        let buffer_size = stride * height * bytes_per_pixel;
        let buffer = unsafe { from_raw_parts_mut(frame_buffer.addr(), buffer_size) };

        Self {
            buffer,
            width,
            height,
            stride,
            bytes_per_pixel,
            pixel_format,
        }
    }
}

impl DrawTarget for Display {
    fn size(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    #[inline(always)]
    fn draw_pixel(&mut self, x: usize, y: usize, color: Rgb) {
        let byte_offset = (y * self.stride + x) * self.bytes_per_pixel;
        let write_range = byte_offset..(byte_offset + self.bytes_per_pixel);

        let color = match self.pixel_format {
            PixelFormat::Rgb => [color.0, color.1, color.2, 0],
            PixelFormat::Bgr => [color.2, color.1, color.0, 0],
            PixelFormat::U8 => unimplemented!(),
            PixelFormat::Unknown => return,
        };

        self.buffer[write_range].copy_from_slice(&color[..self.bytes_per_pixel]);
    }
}

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
    let buf = core::slice::from_raw_parts(buf as *const u8, len + 1);
    let cstr = CStr::from_bytes_with_nul_unchecked(buf);
    let str = cstr.to_str().unwrap();

    crate::print!("{}", str);
}

#[unsafe(no_mangle)]
unsafe extern "C" fn os_terminal_get_screen_info(
    addr: *mut usize,
    width: *mut usize,
    height: *mut usize,
    bpp: *mut usize,
    cols: *mut usize,
    rows: *mut usize,
) {
    let frame_buffer = FRAMEBUFFER_RESPONSE.framebuffers().next().take().unwrap();
    addr.write(frame_buffer.addr() as usize);
    width.write(frame_buffer.width() as usize);
    height.write(frame_buffer.height() as usize);
    bpp.write(frame_buffer.bpp() as usize);
    cols.write(TERMINAL.lock().columns());
    rows.write(TERMINAL.lock().rows());
}

#[unsafe(no_mangle)]
unsafe extern "C" fn os_terminal_get_screen_info_red_green_blue(
    red: *mut usize,
    blue: *mut usize,
    green: *mut usize,
    red1: *mut usize,
    blue1: *mut usize,
    green1: *mut usize,
) {
    let frame_buffer = FRAMEBUFFER_RESPONSE.framebuffers().next().take().unwrap();
    red.write(frame_buffer.red_mask_shift() as usize);
    blue.write(frame_buffer.blue_mask_shift() as usize);
    green.write(frame_buffer.green_mask_shift() as usize);
    red1.write(frame_buffer.red_mask_size() as usize);
    blue1.write(frame_buffer.blue_mask_size() as usize);
    green1.write(frame_buffer.green_mask_size() as usize);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => (
        $crate::libs::os_terminal::_print(
            format_args!($($arg)*)
        )
    )
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)))
}
