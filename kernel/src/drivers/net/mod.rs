#[cfg(target_arch = "x86_64")]
pub mod rtl8139;

#[unsafe(no_mangle)]
extern "C" fn net_init() {}
