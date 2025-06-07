pub mod e1000;

#[unsafe(no_mangle)]
extern "C" fn net_init() {
    e1000::init();
}
