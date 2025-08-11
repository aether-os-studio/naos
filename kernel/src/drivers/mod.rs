pub mod block;
pub mod bus;
pub mod net;
pub mod virtio;

#[cfg(target_arch = "x86_64")]
pub mod serial;
