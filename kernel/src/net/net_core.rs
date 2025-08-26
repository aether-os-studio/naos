use alloc::vec::Vec;
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{self, dhcpv4::Event},
    time::{Duration, Instant},
};
use spin::{Lazy, Mutex, Once};

use crate::{
    net::netdev::{NetDeviceDriver, NetDriver, set_ipv4_addr},
    println,
    rust::bindings::bindings::{
        arch_disable_interrupt, arch_enable_interrupt, arch_yield, get_default_netdev, mktime,
        nanoTime, task_create, task_exit, time_read, tm,
    },
};

pub static SOCKET_SET: Lazy<Mutex<SocketSet<'static>>> =
    Lazy::new(|| Mutex::new(SocketSet::new(Vec::new())));

pub static DHCP_SOCKET_HANDLE: Once<SocketHandle> = Once::new();

pub fn get_current_instant() -> Instant {
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
    let time = unsafe { mktime(&mut time as *mut tm) };
    unsafe { Instant::from_micros(time * 1_000_000_000 + nanoTime() as i64 % 1_000_000_000) }
}

fn delay(ms: u64) {
    if ms == 0 {
        return;
    }

    let nanos = ms * 1_000_000;
    unsafe {
        let start_time = nanoTime();
        while {
            let current_time = nanoTime();
            let elapsed = current_time - start_time;
            elapsed < nanos
        } {
            arch_yield();
        }
    }
}

unsafe extern "C" fn net_helper_entry(_arg: u64) {
    println!("Network helper starting...");

    let mut net_device_driver = NetDeviceDriver::new(get_default_netdev());
    let mut net_driver = NetDriver::new(&mut net_device_driver);

    loop {
        arch_disable_interrupt();

        let mut socket_set = SOCKET_SET.lock();

        net_driver.iface.lock().poll(
            get_current_instant(),
            &mut net_driver.driver,
            &mut socket_set,
        );

        let dhcp_socket: &mut socket::dhcpv4::Socket =
            socket_set.get_mut(DHCP_SOCKET_HANDLE.get().unwrap().clone());
        let event = dhcp_socket.poll();

        match event {
            None => {}
            Some(Event::Deconfigured) => {
                println!("DHCP lost config!");
                net_driver
                    .iface
                    .lock()
                    .update_ip_addrs(|addrs| addrs.clear());
                net_driver
                    .iface
                    .lock()
                    .routes_mut()
                    .remove_default_ipv4_route();
            }
            Some(Event::Configured(config)) => {
                println!("DHCP config acquired!");
                println!("IP address: {}", config.address);
                set_ipv4_addr(&mut net_driver.iface.lock(), config.address);

                if let Some(router) = config.router {
                    println!("Default gateway: {}", router);
                    net_driver
                        .iface
                        .lock()
                        .routes_mut()
                        .add_default_ipv4_route(router)
                        .unwrap();
                } else {
                    println!("Default gateway: None");
                    net_driver
                        .iface
                        .lock()
                        .routes_mut()
                        .remove_default_ipv4_route();
                }

                break;
            }
        }

        drop(socket_set);
        arch_enable_interrupt();

        delay(1000);
    }

    loop {
        arch_disable_interrupt();
        let mut socket_set = SOCKET_SET.lock();
        let time_stamp = get_current_instant();
        net_driver
            .iface
            .lock()
            .poll(time_stamp, &mut net_driver.driver, &mut socket_set);
        drop(socket_set);

        arch_enable_interrupt();

        delay(10);
    }
}

#[unsafe(no_mangle)]
extern "C" fn net_init() {
    if !(unsafe { get_default_netdev() }.is_null()) {
        let mut dhcp_socket = socket::dhcpv4::Socket::new();
        dhcp_socket.reset();
        dhcp_socket.set_max_lease_duration(Some(Duration::from_secs(128)));
        let dhcp_socket_handle = SOCKET_SET.lock().add(dhcp_socket);

        DHCP_SOCKET_HANDLE.call_once(|| dhcp_socket_handle);

        unsafe {
            task_create(
                "net-helper\0".as_ptr() as *const core::ffi::c_char,
                Some(net_helper_entry),
                0,
            )
        };
    }
}
