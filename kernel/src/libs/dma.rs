use core::{
    mem::{self, MaybeUninit},
    ops::{Deref, DerefMut},
    ptr,
};

use crate::{
    mm::phys_to_virt,
    rust::bindings::bindings::{
        DEFAULT_PAGE_SIZE, alloc_frames, get_current_page_dir, unmap_page_range,
    },
};

/// A safe accessor for DMA memory.
pub struct Dma<T: ?Sized> {
    /// The physical address of the memory
    phys: usize,
    /// The page-aligned length of the memory. Will be a multiple of [PAGE_SIZE]
    aligned_len: usize,
    /// The pointer to the Dma memory in the virtual address space.
    virt: *mut T,
}

impl<T> Dma<T> {
    /// [Dma] constructor that allocates and initializes a region of DMA memory with the page-aligned
    /// size and initial value of some T
    ///
    /// # Arguments
    /// 'value: T' - The initial value to write to the allocated region
    ///
    /// # Returns
    ///
    /// This function returns a [Result] containing the following:
    ///
    /// - A '[Ok] (`[Dma]<T>`)' containing the initialized region
    /// - An '[Err]' containing an error.
    pub fn new(value: T) -> Result<Self, ()> {
        unsafe {
            let mut zeroed = Self::zeroed()?;
            zeroed.as_mut_ptr().write(value);
            Ok(zeroed.assume_init())
        }
    }

    /// [Dma] constructor that allocates and zeroizes a memory region of the page-aligned size of T
    ///
    /// # Returns
    ///
    /// This function returns a [Result] containing the following:
    ///
    /// - A '[Ok] (`[Dma]<[MaybeUninit]<T>>`)' containing the allocated and zeroized memory
    /// - An '[Err]' containing an error.
    pub fn zeroed() -> Result<Dma<MaybeUninit<T>>, ()> {
        let aligned_len = size_of::<T>().next_multiple_of(DEFAULT_PAGE_SIZE as usize);
        let phys = unsafe { alloc_frames(aligned_len / DEFAULT_PAGE_SIZE as usize) } as usize;
        let virt = phys_to_virt(phys as usize) as *mut T;
        Ok(Dma {
            phys,
            virt: virt.cast(),
            aligned_len,
        })
    }
}

impl<T> Dma<MaybeUninit<T>> {
    /// Assumes that possibly uninitialized DMA memory has been initialized, and returns a new
    /// instance of an object of type `[Dma]<T>`.
    ///
    /// # Returns
    /// - `[Dma]<T>` - The original structure without the [MaybeUninit] wrapper around its contents.
    ///
    /// # Notes
    /// - This is unsafe because it assumes that the memory stored within the `[Dma]<T>` is a valid
    ///   instance of T. If it isn't (for example -- if it was initialized with [Dma::zeroed]),
    ///   then the underlying memory may not contain the expected T structure.
    pub unsafe fn assume_init(self) -> Dma<T> {
        let Dma {
            phys,
            aligned_len,
            virt,
        } = self;
        mem::forget(self);

        Dma {
            phys,
            aligned_len,
            virt: virt.cast(),
        }
    }
}
impl<T: ?Sized> Dma<T> {
    /// Returns the physical address of the physical memory that this [Dma] structure references.
    ///
    /// # Returns
    /// [usize] - The physical address of the memory.
    pub fn physical(&self) -> usize {
        self.phys
    }
}

impl<T> Dma<[T]> {
    /// Returns a [Dma] object containing a zeroized slice of T with a given count.
    ///
    /// # Arguments
    ///
    /// - 'count: [usize]' - The number of elements of type T in the allocated slice.
    pub fn zeroed_slice(count: usize) -> Result<Dma<[MaybeUninit<T>]>, ()> {
        let aligned_len = count
            .checked_mul(size_of::<T>())
            .unwrap()
            .next_multiple_of(DEFAULT_PAGE_SIZE as usize);
        let phys = unsafe { alloc_frames(aligned_len / DEFAULT_PAGE_SIZE as usize) } as usize;
        let virt = phys_to_virt(phys as usize) as *mut T;

        Ok(Dma {
            phys,
            aligned_len,
            virt: ptr::slice_from_raw_parts_mut(virt.cast(), count),
        })
    }

    /// Casts the slice from type T to type U.
    ///
    /// # Returns
    /// '`[DMA]<U>`' - A cast handle to the Dma memory.
    pub unsafe fn cast_slice<U>(self) -> Dma<[U]> {
        let Dma {
            phys,
            virt,
            aligned_len,
        } = self;
        core::mem::forget(self);

        Dma {
            phys,
            virt: virt as *mut [U],
            aligned_len,
        }
    }
}
impl<T> Dma<[MaybeUninit<T>]> {
    /// See [`Dma<MaybeUninit<T>>::assume_init`]
    pub unsafe fn assume_init(self) -> Dma<[T]> {
        let &Dma {
            phys,
            aligned_len,
            virt,
        } = &self;
        mem::forget(self);

        Dma {
            phys,
            aligned_len,
            virt: virt as *mut [T],
        }
    }
}

impl<T: ?Sized> Deref for Dma<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.virt }
    }
}

impl<T: ?Sized> DerefMut for Dma<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.virt }
    }
}

impl<T: ?Sized> Drop for Dma<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::drop_in_place(self.virt);
            unmap_page_range(
                get_current_page_dir(false),
                self.virt as *const () as u64,
                self.aligned_len as u64,
            );
        }
    }
}
