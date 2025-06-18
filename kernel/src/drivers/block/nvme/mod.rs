use core::alloc::Layout;

use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use nvme::{Allocator, Device, IoQueuePair, Namespace};
use spin::{Lazy, Mutex};

use crate::{
    mm::{phys_to_virt, virt_to_phys},
    rust::bindings::bindings::{
        DEFAULT_PAGE_SIZE, MAX_NVME_DEVICE_NUM, PT_FLAG_R, PT_FLAG_W, alloc_frames, free_frames,
        get_current_page_dir, map_page_range, nvme_handle_t, pci_device_t, pci_find_class,
        translate_address,
    },
};

pub static BUFFERS: Mutex<BTreeMap<usize, Layout>> = Mutex::new(BTreeMap::new());

type LockedQueuePair = Arc<Mutex<IoQueuePair<NvmeAllocator>>>;

pub struct NvmeAllocator;

impl Allocator for NvmeAllocator {
    unsafe fn allocate(&self, size: usize) -> usize {
        let buffer = phys_to_virt(alloc_frames(size / DEFAULT_PAGE_SIZE as usize) as usize);
        let layout = Layout::from_size_align_unchecked(size, DEFAULT_PAGE_SIZE as usize);
        BUFFERS.lock().insert(buffer, layout.clone());
        buffer
    }

    unsafe fn deallocate(&self, addr: usize) {
        if let Some(layout) = BUFFERS.lock().get(&addr) {
            free_frames(virt_to_phys(addr) as u64, layout.size() as u64);
        }
    }

    fn translate(&self, addr: usize) -> usize {
        unsafe { translate_address(get_current_page_dir(false), addr as u64) as usize }
    }
}

pub struct NvmeBlockDevice {
    pub namespace: Namespace,
    pub qpairs: BTreeMap<u16, LockedQueuePair>,
}

pub static IO_PAIRS: Mutex<BTreeMap<usize, BTreeMap<usize, BTreeMap<u16, LockedQueuePair>>>> =
    Mutex::new(BTreeMap::new());

#[unsafe(no_mangle)]
extern "C" fn nvme_init_rs(handles: *mut nvme_handle_t) {
    let mut connections = Vec::new();

    let nvme_devices: &mut [*mut pci_device_t; MAX_NVME_DEVICE_NUM as usize] =
        &mut [core::ptr::null_mut(); MAX_NVME_DEVICE_NUM as usize];

    let mut nvme_device_num: u32 = 0;

    unsafe {
        pci_find_class(
            nvme_devices as *mut *mut pci_device_t,
            &mut nvme_device_num as *mut u32,
            0x010802,
        );
    }

    if nvme_device_num == 0 {
        return;
    }

    for i in 0..nvme_device_num as usize {
        let pci_device = unsafe { *nvme_devices[i] };

        let bar = pci_device.bars[0];

        let (address, size) = (bar.address, bar.size);
        let physical_address = address as u64;
        let virtual_address = phys_to_virt(physical_address as usize) as u64;

        unsafe {
            map_page_range(
                get_current_page_dir(false),
                virtual_address,
                physical_address,
                size,
                PT_FLAG_R as u64 | PT_FLAG_W as u64,
            )
        };

        let virtual_address = virtual_address as usize;
        let device = Device::init(virtual_address, NvmeAllocator).unwrap();
        connections.push(Arc::new(Mutex::new(device)));
    }

    let handles = unsafe { core::slice::from_raw_parts_mut(handles, MAX_NVME_DEVICE_NUM as usize) };

    let mut idx = 0;

    let mut m = 0;

    connections.iter().for_each(|device| {
        let devices: Vec<NvmeBlockDevice> = {
            let mut controller = device.lock();
            let namespaces = controller.identify_namespaces(0).unwrap();

            let mapper = |namespace: Namespace| {
                let qpair = controller
                    .create_io_queue_pair(namespace.clone(), 64)
                    .ok()?;

                Some(NvmeBlockDevice {
                    namespace,
                    qpairs: BTreeMap::from([(*qpair.id(), Arc::new(Mutex::new(qpair)))]),
                })
            };

            namespaces.into_iter().filter_map(mapper).collect()
        };

        let mut nvme_devices = BTreeMap::new();

        for (n, device) in devices.iter().enumerate() {
            let mut io_queue_pairs = BTreeMap::new();

            handles[idx].major_id = m as u64;
            handles[idx].minor_id = n as u64;
            for (&id, qpair) in device.qpairs.iter() {
                io_queue_pairs.insert(id, qpair.clone());
            }

            let mut k = 0;
            for (&id, _) in io_queue_pairs.iter() {
                handles[idx].qpairs[k] = id;
                k += 1;
            }

            handles[idx].max_size = device.namespace.block_count() * device.namespace.block_size();
            if k != 0 {
                handles[idx].valid = true;
            }

            idx += 1;

            nvme_devices.insert(n, io_queue_pairs);
        }
        IO_PAIRS.lock().insert(m, nvme_devices);

        m += 1;
    });
}

#[unsafe(no_mangle)]
extern "C" fn nvme_read_rs(
    major: usize,
    minor: usize,
    qpair_id: u16,
    lba: u64,
    buffer: u64,
    bytes: u64,
) -> u64 {
    let q_pairs = IO_PAIRS.lock();
    let device = q_pairs.get(&major).unwrap();
    let pairs = device.get(&minor).unwrap();
    let pair = pairs.get(&qpair_id).unwrap();

    if let Err(_) = pair.lock().read(buffer as *mut u8, bytes as usize, lba) {
        return 0;
    }

    return bytes;
}

#[unsafe(no_mangle)]
extern "C" fn nvme_write_rs(
    major: usize,
    minor: usize,
    qpair_id: u16,
    lba: u64,
    buffer: u64,
    bytes: u64,
) -> u64 {
    let q_pairs = IO_PAIRS.lock();
    let device = q_pairs.get(&major).unwrap();
    let pairs = device.get(&minor).unwrap();
    let pair = pairs.get(&qpair_id).unwrap();

    if let Err(_) = pair.lock().write(buffer as *const u8, bytes as usize, lba) {
        return 0;
    }

    return bytes;
}
