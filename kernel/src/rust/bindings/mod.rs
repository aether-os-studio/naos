#[cfg(target_arch = "aarch64")]
pub mod bindings_aarch64;
#[cfg(target_arch = "x86_64")]
pub mod bindings_x86_64;

pub mod bindings {
    #[cfg(target_arch = "aarch64")]
    pub use super::bindings_aarch64::*;
    #[cfg(target_arch = "x86_64")]
    pub use super::bindings_x86_64::*;
}
