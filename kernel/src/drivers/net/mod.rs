#[cfg(target_arch = "x86_64")]
pub mod e1000;

pub mod virtio;

#[unsafe(no_mangle)]
extern "C" fn net_init() {
    #[cfg(target_arch = "x86_64")]
    e1000::init();

    virtio::init();
}
