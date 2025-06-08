#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::hint::spin_loop;
use core::mem::size_of;
use core::sync::atomic::{Ordering, fence};
use smoltcp::socket::Socket;
use smoltcp::socket::dhcpv4::Event;
use spin::{Lazy, Mutex, RwLock};

use bit_field::*;
use bitflags::*;

use smoltcp::phy::{self, DeviceCapabilities};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::*;
use smoltcp::{iface::*, socket};

use crate::mm::phys_to_virt;
use crate::net::{NetworkDevice, SOCKETS, SOCKETS_SET};
use crate::rust::bindings::bindings::{
    DEFAULT_PAGE_SIZE, PT_FLAG_R, PT_FLAG_W, alloc_frames, apic_controller, arch_enable_interrupt,
    arch_yield, get_current_page_dir, irq_controller_t, irq_regist_irq, map_page_range, mktime,
    pci_device_t, pci_find_class, pt_regs, task_create, task_exit, time_read, tm,
};
use crate::{println, ref_to_mut};

// At the beginning, all transmit descriptors have there status non-zero,
// so we need to track whether we are using the descriptor for the first time.
// When the descriptors wrap around, we set first_trans to false,
// and lookup status instead for checking whether it is empty.

pub struct E1000 {
    header: usize,
    size: usize,
    mac: EthernetAddress,
    registers: &'static mut [u32],
    send_queue: &'static mut [E1000SendDesc],
    send_buffers: Vec<usize>,
    recv_queue: &'static mut [E1000RecvDesc],
    recv_buffers: Vec<usize>,
    first_trans: bool,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct E1000SendDesc {
    addr: u64,
    len: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct E1000RecvDesc {
    addr: u64,
    len: u16,
    chksum: u16,
    status: u16,
    error: u8,
    special: u8,
}

bitflags! {
    #[derive(Debug)]
    struct E1000Status : u32 {
        const FD = 1 << 0;
        const LU = 1 << 1;
        const TXOFF = 1 << 4;
        const TBIMODE = 1 << 5;
        const SPEED_100M = 1 << 6;
        const SPEED_1000M = 1 << 7;
        const ASDV_100M = 1 << 8;
        const ASDV_1000M = 1 << 9;
        const MTXCKOK = 1 << 10;
        const PCI66 = 1 << 11;
        const BUS64 = 1 << 12;
        const PCIX_MODE = 1 << 13;
        const GIO_MASTER_ENABLE = 1 << 19;
    }
}

impl E1000 {
    pub fn new(header: usize, size: usize, mac: EthernetAddress) -> Self {
        assert_eq!(size_of::<E1000SendDesc>(), 16);
        assert_eq!(size_of::<E1000RecvDesc>(), 16);

        let send_queue_pa = unsafe { alloc_frames(1) } as usize;
        let send_queue_va = phys_to_virt(send_queue_pa);
        let recv_queue_pa = unsafe { alloc_frames(1) } as usize;
        let recv_queue_va = phys_to_virt(recv_queue_pa);
        let send_queue: &mut [E1000SendDesc] = unsafe {
            core::slice::from_raw_parts_mut(
                send_queue_va as *mut _,
                DEFAULT_PAGE_SIZE as usize / size_of::<E1000SendDesc>(),
            )
        };
        let recv_queue: &mut [E1000RecvDesc] = unsafe {
            core::slice::from_raw_parts_mut(
                recv_queue_va as *mut _,
                DEFAULT_PAGE_SIZE as usize / size_of::<E1000RecvDesc>(),
            )
        };

        let mut send_buffers = Vec::with_capacity(send_queue.len());
        let mut recv_buffers = Vec::with_capacity(recv_queue.len());

        let e1000: &mut [u32] =
            unsafe { core::slice::from_raw_parts_mut(header as *mut _, size / 4) };

        // 4.6 Software Initialization Sequence

        // 4.6.6 Transmit Initialization

        // Program the descriptor base address with the address of the region.
        e1000[E1000_TDBAL] = send_queue_pa as u32; // TDBAL
        e1000[E1000_TDBAH] = (send_queue_pa >> 32) as u32; // TDBAH

        // Set the length register to the size of the descriptor ring.
        e1000[E1000_TDLEN] = DEFAULT_PAGE_SIZE; // TDLEN

        // If needed, program the head and tail registers.
        e1000[E1000_TDH] = 0; // TDH
        e1000[E1000_TDT] = 0; // TDT

        for i in 0..send_queue.len() {
            let buffer_page_pa = unsafe { alloc_frames(1) } as usize;
            let buffer_page_va = phys_to_virt(buffer_page_pa);
            send_queue[i].addr = buffer_page_pa as u64;
            send_buffers.push(buffer_page_va as usize);
        }

        // EN | PSP | CT=0x10 | COLD=0x40
        e1000[E1000_TCTL] = (1 << 1) | (1 << 3) | (0x10 << 4) | (0x40 << 12); // TCTL
        // IPGT=0xa | IPGR1=0x8 | IPGR2=0xc
        e1000[E1000_TIPG] = 0xa | (0x8 << 10) | (0xc << 20); // TIPG

        // 4.6.5 Receive Initialization
        let mut ral: u32 = 0;
        let mut rah: u32 = 0;
        for i in 0..4 {
            ral = ral | (mac.as_bytes()[i] as u32) << (i * 8);
        }
        for i in 0..2 {
            rah = rah | (mac.as_bytes()[i + 4] as u32) << (i * 8);
        }

        e1000[E1000_RAL] = ral; // RAL
        // AV | AS=DA
        e1000[E1000_RAH] = rah | (1 << 31); // RAH

        // MTA
        for i in E1000_MTA..E1000_RAL {
            e1000[i] = 0;
        }

        // Program the descriptor base address with the address of the region.
        e1000[E1000_RDBAL] = recv_queue_pa as u32; // RDBAL
        e1000[E1000_RDBAH] = (recv_queue_pa >> 32) as u32; // RDBAH

        // Set the length register to the size of the descriptor ring.
        e1000[E1000_RDLEN] = DEFAULT_PAGE_SIZE; // RDLEN

        // If needed, program the head and tail registers. Note: the head and tail pointers are initialized (by hardware) to zero after a power-on or a software-initiated device reset.
        e1000[E1000_RDH] = 0; // RDH

        // The tail pointer should be set to point one descriptor beyond the end.
        e1000[E1000_RDT] = (recv_queue.len() - 1) as u32; // RDT

        // Receive buffers of appropriate size should be allocated and pointers to these buffers should be stored in the descriptor ring.
        for i in 0..recv_queue.len() {
            let buffer_page_pa = unsafe { alloc_frames(1) } as usize;
            let buffer_page_va = phys_to_virt(buffer_page_pa);
            recv_queue[i].addr = buffer_page_pa as u64;
            recv_buffers.push(buffer_page_va as usize);
        }

        e1000[E1000_RCTL] = (1 << 1) | (1 << 15) | (1 << 16) | (1 << 26); // RCTL

        // RXT0
        e1000[E1000_IMS] = 1 << 7; // IMS

        E1000 {
            header,
            size,
            mac,
            registers: e1000,
            send_queue,
            send_buffers,
            recv_queue,
            recv_buffers,
            first_trans: true,
        }
    }

    pub fn handle_interrupt(&mut self) -> bool {
        let icr = self.registers[E1000_ICR];

        if icr != 0 {
            // clear it
            self.registers[E1000_ICR] = icr;
            true
        } else {
            false
        }
    }

    pub fn receive(&mut self) -> Option<Vec<u8>> {
        let rdt = self.registers[E1000_RDT] as usize;
        let index = (rdt + 1) % self.recv_queue.len();
        let recv_desc = &mut self.recv_queue[index];

        if !recv_desc.status.get_bit(0) {
            // 只检查接收描述符状态
            return None;
        }

        let pkt_len = (recv_desc.len as usize).saturating_sub(4);

        let buffer =
            unsafe { core::slice::from_raw_parts(self.recv_buffers[index] as *const _, pkt_len) };

        recv_desc.status = 0;
        recv_desc.addr = self.recv_buffers[index] as u64; // 重新绑定缓冲区地址

        self.registers[E1000_RDT] = index as u32;

        Some(buffer.to_vec())
    }

    pub fn can_send(&self) -> bool {
        let tdt = self.registers[E1000_TDT];
        let index = (tdt as usize) % self.send_queue.len();
        let send_desc = &self.send_queue[index];
        self.first_trans || send_desc.status.get_bit(0)
    }

    pub fn send(&mut self, buffer: &[u8]) {
        let mut tdt = self.registers[E1000_TDT];
        let index = (tdt as usize) % self.send_queue.len();
        let send_desc = &mut self.send_queue[index];
        assert!(self.first_trans || send_desc.status.get_bit(0));

        let target = unsafe {
            core::slice::from_raw_parts_mut(self.send_buffers[index] as *mut _, buffer.len())
        };
        target.copy_from_slice(&buffer);

        send_desc.len = buffer.len() as u16 + 4;
        send_desc.cmd = (1 << 3) | (1 << 1) | (1 << 0); // RS | IFCS | EOP
        send_desc.status = 0;
        fence(Ordering::SeqCst);

        tdt = (tdt + 1) % self.send_queue.len() as u32;
        self.registers[E1000_TDT] = tdt;
        fence(Ordering::SeqCst);

        // round
        if tdt == 0 {
            self.first_trans = false;
        }
    }
}

const E1000_STATUS: usize = 0x0008 / 4;
const E1000_ICR: usize = 0x00C0 / 4;
const E1000_IMS: usize = 0x00D0 / 4;
const E1000_IMC: usize = 0x00D8 / 4;
const E1000_RCTL: usize = 0x0100 / 4;
const E1000_TCTL: usize = 0x0400 / 4;
const E1000_TIPG: usize = 0x0410 / 4;
const E1000_RDBAL: usize = 0x2800 / 4;
const E1000_RDBAH: usize = 0x2804 / 4;
const E1000_RDLEN: usize = 0x2808 / 4;
const E1000_RDH: usize = 0x2810 / 4;
const E1000_RDT: usize = 0x2818 / 4;
const E1000_TDBAL: usize = 0x3800 / 4;
const E1000_TDBAH: usize = 0x3804 / 4;
const E1000_TDLEN: usize = 0x3808 / 4;
const E1000_TDH: usize = 0x3810 / 4;
const E1000_TDT: usize = 0x3818 / 4;
const E1000_MTA: usize = 0x5200 / 4;
const E1000_RAL: usize = 0x5400 / 4;
const E1000_RAH: usize = 0x5404 / 4;

#[derive(Clone)]
pub struct E1000Driver(Arc<E1000>);

pub struct E1000Interface {
    iface: Arc<Interface>,
    driver: E1000Driver,
    name: String,
    irq: Option<usize>,
}

pub struct E1000RxToken(Vec<u8>);
pub struct E1000TxToken(E1000Driver);

impl phy::Device for E1000Driver {
    type RxToken<'a> = E1000RxToken;
    type TxToken<'a> = E1000TxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        ref_to_mut(self.0.as_ref())
            .receive()
            .map(|vec| (E1000RxToken(vec), E1000TxToken(self.clone())))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.0.as_ref().can_send() {
            Some(E1000TxToken(self.clone()))
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1536;
        caps.max_burst_size = Some(64);
        caps
    }
}

impl phy::RxToken for E1000RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl phy::TxToken for E1000TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = [0u8; DEFAULT_PAGE_SIZE as usize];
        let result = f(&mut buffer[..len]);

        let driver = ref_to_mut((self.0).0.as_ref());
        driver.send(&buffer);

        result
    }
}

/// Clear any existing IP addresses & add the new one
fn set_ipv4_addr(iface: &mut Interface, cidr: Ipv4Cidr) {
    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        addrs.push(IpCidr::Ipv4(cidr)).unwrap();
    });
}

fn get_current_instant() -> Instant {
    let mut time: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
    };
    unsafe { time_read(&mut time as *mut tm) };
    Instant::from_millis(unsafe { mktime(&mut time as *mut tm) })
}

pub static mut ACTIVATE_DRIVER: Option<Arc<E1000Interface>> = None;

pub static E1000_DRIVER: Lazy<Mutex<Vec<Arc<E1000Interface>>>> = Lazy::new(|| {
    let devices: &mut [*mut pci_device_t; 8] = &mut [
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    ];
    let mut num: u32 = 0;
    unsafe {
        pci_find_class(
            devices as *mut *mut pci_device_t,
            &mut num as *mut u32,
            0x020000,
        )
    };

    let mut drivers = Vec::new();

    (0..num).for_each(|i| {
        let device = unsafe { &mut *devices[i as usize] };

        let bar_addr = device.bars[0].address;
        let bar_size = device.bars[0].size;
        let vaddr = phys_to_virt(bar_addr as usize);
        unsafe {
            map_page_range(
                get_current_page_dir(false),
                vaddr as u64,
                bar_addr,
                bar_size,
                PT_FLAG_R as u64 | PT_FLAG_W as u64,
            )
        };

        let mac: [u8; 6] = [0x54, 0x51, 0x9F, 0x71, 0xC0, i as u8];
        let e1000 = E1000::new(vaddr, bar_size as usize, EthernetAddress(mac));
        let mut net_driver = E1000Driver(Arc::new(e1000));

        let ethernet_addr = EthernetAddress::from_bytes(&mac);
        let ip_addrs = [IpCidr::new(IpAddress::v4(10, 0, i as u8, 2), 24)];
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = 10;

        let iface = Interface::new(config, &mut net_driver, get_current_instant());

        let interface = Arc::new(E1000Interface {
            iface: Arc::new(iface),
            driver: net_driver.clone(),
            name: format!("eth{}", i),
            irq: Some(device.irq_line as usize),
        });
        drivers.push(interface.clone());

        unsafe {
            if let None = ACTIVATE_DRIVER {
                ACTIVATE_DRIVER.replace(interface);
            }
        }

        unsafe {
            irq_regist_irq(
                device.irq_line as u64 + 32,
                Some(e1000_irq_handler),
                device.irq_line as u64,
                core::ptr::null_mut(),
                &raw mut apic_controller as *mut irq_controller_t,
                "e1000\0".as_ptr() as usize as *mut core::ffi::c_char,
            )
        };
    });

    Mutex::new(drivers)
});

unsafe extern "C" fn e1000_irq_handler(
    irq_num: u64,
    data: *mut ::core::ffi::c_void,
    regs: *mut pt_regs,
) {
    ref_to_mut(ACTIVATE_DRIVER.clone().unwrap().driver.0.as_ref()).handle_interrupt();
}

unsafe extern "C" fn e1000_init_thread(arg: u64) {
    if E1000_DRIVER.lock().len() > 0 {
        let driver = ACTIVATE_DRIVER.clone().unwrap();

        let mut dhcp_socket = socket::dhcpv4::Socket::new();
        dhcp_socket.reset();
        dhcp_socket.set_max_lease_duration(Some(Duration::from_secs(10)));
        let mut set = SocketSet::new(Vec::new());
        let dhcp_socket = set.add(dhcp_socket);

        loop {
            let time_stamp = get_current_instant();
            ref_to_mut(driver.iface.as_ref()).poll(
                time_stamp,
                ref_to_mut(&driver.driver),
                &mut set,
            );

            let dhcp_socket: &mut socket::dhcpv4::Socket = set.get_mut(dhcp_socket);
            let event = dhcp_socket.poll();

            match event {
                None => {}
                Some(Event::Deconfigured) => {
                    ref_to_mut(driver.iface.as_ref()).update_ip_addrs(|addrs| addrs.clear());
                    ref_to_mut(driver.iface.as_ref())
                        .routes_mut()
                        .remove_default_ipv4_route();
                }
                Some(Event::Configured(config)) => {
                    // println!("DHCP config acquired!");

                    // println!("IP address: {}", config.address);
                    set_ipv4_addr(&mut ref_to_mut(driver.iface.as_ref()), config.address);

                    if let Some(router) = config.router {
                        // println!("Default gateway: {}", router);
                        ref_to_mut(driver.iface.as_ref())
                            .routes_mut()
                            .add_default_ipv4_route(router)
                            .unwrap();
                    } else {
                        // println!("Default gateway: None");
                        ref_to_mut(driver.iface.as_ref())
                            .routes_mut()
                            .remove_default_ipv4_route();
                    }
                }
            }

            ref_to_mut(driver.iface.as_ref()).poll_delay(time_stamp, &set);

            ref_to_mut(driver.iface.as_ref()).poll(
                get_current_instant(),
                ref_to_mut(&driver.driver),
                &mut SOCKETS_SET.lock(),
            );

            arch_enable_interrupt();

            spin_loop();
        }
    } else {
        unsafe { task_exit(-1) };
        unreachable!()
    }
}

pub fn init() {
    unsafe {
        task_create("e1000\0".as_ptr() as _, Some(e1000_init_thread), 0);
    }
}
