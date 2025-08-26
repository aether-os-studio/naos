use alloc::{sync::Arc, vec::Vec};
use smoltcp::{
    iface::{Config, Interface},
    phy::{self, DeviceCapabilities},
    time::Instant,
    wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Cidr},
};
use spin::{Lazy, Mutex};

use crate::{
    net::net_core::get_current_instant,
    rust::bindings::bindings::{get_default_netdev, netdev_recv, netdev_send, netdev_t},
};

pub struct NetDevice {
    pub inner: *mut netdev_t,
}

#[derive(Clone)]
pub struct NetDeviceDriver(Arc<Mutex<NetDevice>>);

impl NetDeviceDriver {
    pub fn new(inner: *mut netdev_t) -> Self {
        Self(Arc::new(Mutex::new(NetDevice { inner })))
    }
}

unsafe impl Send for NetDevice {}
unsafe impl Sync for NetDevice {}

pub struct NetDeviceRxToken(Vec<u8>);
pub struct NetDeviceTxToken(NetDeviceDriver);

impl phy::Device for NetDeviceDriver {
    type RxToken<'a> = NetDeviceRxToken;
    type TxToken<'a> = NetDeviceTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buffer = [0u8; 4096];

        let count = unsafe {
            netdev_recv(
                self.0.lock().inner,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                buffer.len() as u32,
            )
        } as usize;

        if count > 0 {
            Some((
                NetDeviceRxToken(buffer[..count].to_vec()),
                NetDeviceTxToken(self.clone()),
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(NetDeviceTxToken(self.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = unsafe { *self.0.lock().inner }.mtu as usize;
        caps.max_burst_size = Some(64);
        caps
    }
}

impl phy::RxToken for NetDeviceRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

impl phy::TxToken for NetDeviceTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = [0u8; 4096];
        let result = f(&mut buffer[..len]);

        unsafe {
            netdev_send(
                self.0.0.lock().inner,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                len as u32,
            )
        };

        result
    }
}

pub struct NetDriver {
    pub driver: NetDeviceDriver,
    pub iface: Mutex<Interface>,
}

impl NetDriver {
    pub fn new(driver: &mut NetDeviceDriver) -> Self {
        let ethernet_addr = EthernetAddress::from_bytes(&unsafe { *driver.0.lock().inner }.mac);
        let ip_addrs = [IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24)];
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(
            unsafe { *driver.0.lock().inner }.mac,
        )));
        config.random_seed = 10;

        Self {
            driver: driver.clone(),
            iface: Mutex::new(Interface::new(config, driver, get_current_instant())),
        }
    }
}

pub static DEFAULT_NETDEV: Lazy<Mutex<NetDriver>> = Lazy::new(|| {
    Mutex::new(NetDriver::new(&mut NetDeviceDriver::new(unsafe {
        get_default_netdev()
    })))
});

pub static IPV4_ADDR: Mutex<Option<Ipv4Cidr>> = Mutex::new(None);

pub fn set_ipv4_addr(iface: &mut Interface, cidr: Ipv4Cidr) {
    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        addrs.push(IpCidr::Ipv4(cidr)).unwrap();
    });
    *IPV4_ADDR.lock() = Some(cidr.clone());
}
