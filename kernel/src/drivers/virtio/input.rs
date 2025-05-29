use core::hint::spin_loop;

use alloc::vec::Vec;
use crossbeam_queue::ArrayQueue;
use spin::{Lazy, Mutex, MutexGuard};
use virtio_drivers::{Error, device::input::VirtIOInput, transport::pci::PciTransport};

use crate::rust::bindings::bindings::task_create;

use super::{
    decode::{DecodeType, Decoder},
    hal::HalImpl,
};

struct VirtIOInputDriver(Mutex<VirtIOInput<HalImpl, PciTransport>>);

impl VirtIOInputDriver {
    pub fn new(transport: PciTransport) -> Result<VirtIOInputDriver, Error> {
        Ok(Self(Mutex::new(VirtIOInput::new(transport)?)))
    }

    pub fn lock(&self) -> MutexGuard<'_, VirtIOInput<HalImpl, PciTransport>> {
        self.0.lock()
    }
}

static INPUT_DRIVERS: Mutex<Vec<VirtIOInputDriver>> = Mutex::new(Vec::new());

pub const SCANCODE_QUEUE_SIZE: usize = 1024;
static SCANCODE_QUEUE: Lazy<ArrayQueue<u8>> = Lazy::new(|| ArrayQueue::new(SCANCODE_QUEUE_SIZE));

unsafe extern "C" fn virtio_input_kthread() {
    loop {
        for device in INPUT_DRIVERS.lock().iter() {
            if let Some(event) = device.lock().pop_pending_event() {
                let decode = Decoder::decode(
                    event.event_type as usize,
                    event.code as usize,
                    event.value as usize,
                );
                if let Ok(code) = decode {
                    if let DecodeType::Key(key, ty) = code {
                        SCANCODE_QUEUE
                            .push(key.to_char().unwrap() as u8)
                            .expect("keyboard buffer full!!!");
                    } else if let DecodeType::Mouse(mouse) = code {
                    }
                }
            }
        }

        spin_loop();
    }
}

#[unsafe(no_mangle)]
extern "C" fn push_char(c: u8) {
    SCANCODE_QUEUE.push(c).expect("keyboard buffer full!!!");
}

#[unsafe(no_mangle)]
extern "C" fn get_keyboard_input_queue() -> u8 {
    SCANCODE_QUEUE.pop().or(Some(0)).unwrap()
}

pub fn init_pci(transport: PciTransport) {
    if let Ok(device) = VirtIOInputDriver::new(transport) {
        if INPUT_DRIVERS.lock().len() == 0 {
            unsafe {
                task_create(
                    "Virtio input kthread".as_ptr() as *const core::ffi::c_char,
                    Some(virtio_input_kthread),
                );
            }
        }
        INPUT_DRIVERS.lock().push(device);
    }
}
