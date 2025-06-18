#[cfg(target_arch = "x86_64")]
pub mod e1000;

#[unsafe(no_mangle)]
extern "C" fn net_init() {
    #[cfg(target_arch = "x86_64")]
    e1000::init();

    crate::drivers::virtio::net::init();
}
