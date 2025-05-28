use core::{
    mem::MaybeUninit,
    ops::{BitAnd, BitOr, Not},
    ptr,
};

pub trait Io {
    /// Value type for IO, usually some unsigned number
    type Value: Copy
        + PartialEq
        + BitAnd<Output = Self::Value>
        + BitOr<Output = Self::Value>
        + Not<Output = Self::Value>;

    /// Read the underlying valu2e
    fn read(&self) -> Self::Value;
    /// Write the underlying value
    fn write(&mut self, value: Self::Value);

    /// Check whether the underlying value contains bit flags
    #[inline(always)]
    fn readf(&self, flags: Self::Value) -> bool {
        (self.read() & flags) == flags
    }

    /// Enable or disable specific bit flags
    #[inline(always)]
    fn writef(&mut self, flags: Self::Value, value: bool) {
        let tmp: Self::Value = match value {
            true => self.read() | flags,
            false => self.read() & !flags,
        };
        self.write(tmp);
    }
}

/// MMIO abstraction
#[repr(C, packed)]
pub struct Mmio<T> {
    value: MaybeUninit<T>,
}

impl<T> Mmio<T> {
    /// Creates a zeroed instance
    pub unsafe fn zeroed() -> Self {
        Self {
            value: MaybeUninit::zeroed(),
        }
    }

    /// Creates an unitialized instance
    pub unsafe fn uninit() -> Self {
        Self {
            value: MaybeUninit::uninit(),
        }
    }

    /// Creates a new instance
    pub const fn new(value: T) -> Self {
        Self {
            value: MaybeUninit::new(value),
        }
    }
}

impl<T> Io for Mmio<T>
where
    T: Copy
        + PartialEq
        + core::ops::BitAnd<Output = T>
        + core::ops::BitOr<Output = T>
        + core::ops::Not<Output = T>,
{
    type Value = T;

    fn read(&self) -> T {
        unsafe { ptr::read_volatile(ptr::addr_of!(self.value).cast::<T>()) }
    }

    fn write(&mut self, value: T) {
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(self.value).cast::<T>(), value) };
    }
}
