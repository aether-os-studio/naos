use core::hint::spin_loop;

use alloc::{string::String, sync::Arc, vec::Vec};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{self, DeviceCapabilities},
    socket::{self, dhcpv4::Event},
    time::{Duration, Instant},
    wire::{EthernetAddress, IpCidr, Ipv4Cidr},
};
use spin::{Lazy, Mutex};
use virtio_drivers::{
    device::net::{TxBuffer, VirtIONet},
    transport::pci::PciTransport,
};

use crate::{
    drivers::virtio::hal::HalImpl,
    net::net_core::SOCKETS_SET,
    println, ref_to_mut,
    rust::bindings::bindings::{
        DEFAULT_PAGE_SIZE, arch_enable_interrupt, mktime, task_create, task_exit, time_read, tm,
    },
};

#[derive(Clone)]
pub struct VirtIONetDriver(Arc<VirtIONet<HalImpl, PciTransport, 64>>);

pub struct VirtIONetInterface {
    iface: Arc<Interface>,
    driver: VirtIONetDriver,
}

pub struct VirtIONetRxToken(Vec<u8>);
pub struct VirtIONetTxToken(VirtIONetDriver);

impl phy::Device for VirtIONetDriver {
    type RxToken<'a> = VirtIONetRxToken;
    type TxToken<'a> = VirtIONetTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        ref_to_mut(self.0.as_ref())
            .receive()
            .map(|vec| {
                (
                    VirtIONetRxToken(vec.as_bytes().to_vec()),
                    VirtIONetTxToken(self.clone()),
                )
            })
            .ok()
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.0.as_ref().can_send() {
            Some(VirtIONetTxToken(self.clone()))
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 256;
        caps.max_burst_size = Some(64);
        caps
    }
}

impl phy::RxToken for VirtIONetRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl phy::TxToken for VirtIONetTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = [0u8; DEFAULT_PAGE_SIZE as usize];
        let result = f(&mut buffer[..len]);

        let driver = ref_to_mut((self.0).0.as_ref());
        let _ = driver.send(TxBuffer::from(&buffer));

        result
    }
}

pub static mut ACTIVATE_DRIVER: Option<Arc<VirtIONetInterface>> = None;

pub static VIRTIO_NET_DRIVER: Mutex<Vec<Arc<VirtIONetInterface>>> = Mutex::new(Vec::new());

pub fn init_pci(transport: PciTransport) {
    if let Ok(net) = VirtIONet::new(transport, 1536) {
        let mut net_driver = VirtIONetDriver(Arc::new(net));

        let mac = net_driver.0.mac_address();

        let config = Config::new(smoltcp::wire::HardwareAddress::Ethernet(
            EthernetAddress::from_bytes(&mac),
        ));

        let iface = Interface::new(config, &mut net_driver, get_current_instant());

        let interface = Arc::new(VirtIONetInterface {
            iface: Arc::new(iface),
            driver: net_driver.clone(),
        });

        unsafe { ACTIVATE_DRIVER = Some(interface.clone()) };

        VIRTIO_NET_DRIVER.lock().push(interface);
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

unsafe extern "C" fn virtio_net_init_thread(arg: u64) {
    if VIRTIO_NET_DRIVER.lock().len() > 0 {
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
                    println!("DHCP config acquired!");

                    println!("IP address: {}", config.address);
                    set_ipv4_addr(&mut ref_to_mut(driver.iface.as_ref()), config.address);

                    if let Some(router) = config.router {
                        println!("Default gateway: {}", router);
                        ref_to_mut(driver.iface.as_ref())
                            .routes_mut()
                            .add_default_ipv4_route(router)
                            .unwrap();
                    } else {
                        println!("Default gateway: None");
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

#[unsafe(no_mangle)]
unsafe extern "C" fn virtio_net_init() {
    unsafe {
        task_create(
            "virtio_net\0".as_ptr() as _,
            Some(virtio_net_init_thread),
            0,
        );
    }
}
