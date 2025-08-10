use core::net::{Ipv4Addr, Ipv6Addr};

use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, Socket, raw, udp::UdpMetadata},
    storage::{PacketBuffer, PacketMetadata},
    wire::{IpEndpoint, IpProtocol, IpVersion},
};
use spin::{Lazy, Mutex};

use crate::rust::bindings::bindings::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SocketType {
    Rawv4,
    Rawv6,
    Tcpv4,
    Tcpv6,
    Udpv4,
    Udpv6,
}

pub static SOCKETS_SET: Lazy<Mutex<SocketSet>> =
    Lazy::new(|| Mutex::new(SocketSet::new(Vec::new())));
pub static SOCKETS_TYPE_MAP: Mutex<BTreeMap<SocketHandle, SocketType>> =
    Mutex::new(BTreeMap::new());
pub static SOCKETS: Mutex<BTreeMap<usize, BTreeMap<i32, SocketHandle>>> =
    Mutex::new(BTreeMap::new());
pub static SOCKETS_UDP_CONNECTIONS: Mutex<BTreeMap<usize, BTreeMap<i32, IpEndpoint>>> =
    Mutex::new(BTreeMap::new());

#[unsafe(no_mangle)]
unsafe extern "C" fn socket_on_new_task(pid: usize) {
    SOCKETS.lock().insert(pid, BTreeMap::new());
    SOCKETS_UDP_CONNECTIONS.lock().insert(pid, BTreeMap::new());
}
#[unsafe(no_mangle)]
unsafe extern "C" fn socket_on_exit_task(pid: usize) {
    let mut sockets = SOCKETS.lock();
    if let Some(queue) = sockets.remove(&pid) {
        for (_, handle) in queue {
            SOCKETS_SET.lock().remove(handle);
        }
    }
    let mut sockets_udp_connections = SOCKETS_UDP_CONNECTIONS.lock();
    let _ = sockets_udp_connections.remove(&pid);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn socket_on_dup_file(fd: usize, newfd: usize) {
    let mut sockets = SOCKETS.lock();

    let pid = {
        let task = unsafe { arch_get_current() };
        unsafe { *task }.pid as usize
    };

    let queue = { sockets.get_mut(&pid).unwrap() };

    if let Some(socket) = queue.get(&(fd as i32)) {
        queue.insert(newfd as i32, socket.clone());
    }

    if let Some(queue) = SOCKETS_UDP_CONNECTIONS.lock().get_mut(&pid) {
        if let Some(ep) = queue.get(&(fd as i32)) {
            queue.insert(newfd as i32, ep.clone());
        }
    }
}

const RAW_BUFFER_SIZE: usize = 1536;

unsafe extern "C" {
    fn socket_alloc_fd_net() -> i32;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_socket(domain: i32, ty: i32, protocol: i32) -> i32 {
    let pid = {
        let task = unsafe { arch_get_current() };
        unsafe { *task }.pid as usize
    };

    match domain {
        // AF_INET
        2 => match ty {
            // RAW
            3 => {
                let mut rx_1 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| rx_1.push(PacketMetadata::EMPTY));
                let mut rx_2 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| rx_2.push(0));

                let raw_v4_rx = PacketBuffer::new(rx_1, rx_2);

                let mut tx_1 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| tx_1.push(PacketMetadata::EMPTY));
                let mut tx_2 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| tx_2.push(0));
                let raw_v4_tx = PacketBuffer::new(tx_1, tx_2);

                let socket = raw::Socket::new(
                    IpVersion::Ipv4,
                    IpProtocol::from(protocol as u8),
                    raw_v4_rx,
                    raw_v4_tx,
                );

                let handle = SOCKETS_SET.lock().add(socket);
                SOCKETS_TYPE_MAP.lock().insert(handle, SocketType::Rawv4);

                let fd = socket_alloc_fd_net();

                SOCKETS.lock().get_mut(&pid).unwrap().insert(fd, handle);

                return fd;
            }
            // DGRAM
            2 => {
                let mut rx_1 = Vec::new();
                (0..RAW_BUFFER_SIZE)
                    .for_each(|_| rx_1.push(smoltcp::socket::udp::PacketMetadata::EMPTY));
                let mut rx_2 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| rx_2.push(0));

                let udp_v4_rx = PacketBuffer::new(rx_1, rx_2);

                let mut tx_1 = Vec::new();
                (0..RAW_BUFFER_SIZE)
                    .for_each(|_| tx_1.push(smoltcp::socket::udp::PacketMetadata::EMPTY));
                let mut tx_2 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| tx_2.push(0));
                let udp_v4_tx = PacketBuffer::new(tx_1, tx_2);

                let socket = smoltcp::socket::udp::Socket::new(udp_v4_rx, udp_v4_tx);
                let handle = SOCKETS_SET.lock().add(socket);
                SOCKETS_TYPE_MAP.lock().insert(handle, SocketType::Udpv4);

                let fd = socket_alloc_fd_net();

                SOCKETS.lock().get_mut(&pid).unwrap().insert(fd, handle);

                return fd;
            }
            _ => -(EINVAL as i32),
        },
        // AF_INET6
        10 => match ty {
            // RAW
            3 => {
                let mut rx_1 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| rx_1.push(PacketMetadata::EMPTY));
                let mut rx_2 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| rx_2.push(0));

                let raw_v6_rx = PacketBuffer::new(rx_1, rx_2);

                let mut tx_1 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| tx_1.push(PacketMetadata::EMPTY));
                let mut tx_2 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| tx_2.push(0));
                let raw_v6_tx = PacketBuffer::new(tx_1, tx_2);

                let socket = raw::Socket::new(
                    IpVersion::Ipv6,
                    IpProtocol::from(protocol as u8),
                    raw_v6_rx,
                    raw_v6_tx,
                );

                let handle = SOCKETS_SET.lock().add(socket);
                SOCKETS_TYPE_MAP.lock().insert(handle, SocketType::Rawv6);

                let fd = socket_alloc_fd_net();

                SOCKETS.lock().get_mut(&pid).unwrap().insert(fd, handle);

                return fd;
            }
            // DGRAM
            2 => {
                let mut rx_1 = Vec::new();
                (0..RAW_BUFFER_SIZE)
                    .for_each(|_| rx_1.push(smoltcp::socket::udp::PacketMetadata::EMPTY));
                let mut rx_2 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| rx_2.push(0));

                let udp_v6_rx = PacketBuffer::new(rx_1, rx_2);

                let mut tx_1 = Vec::new();
                (0..RAW_BUFFER_SIZE)
                    .for_each(|_| tx_1.push(smoltcp::socket::udp::PacketMetadata::EMPTY));
                let mut tx_2 = Vec::new();
                (0..RAW_BUFFER_SIZE).for_each(|_| tx_2.push(0));
                let udp_v6_tx = PacketBuffer::new(tx_1, tx_2);

                let socket = smoltcp::socket::udp::Socket::new(udp_v6_rx, udp_v6_tx);
                let handle = SOCKETS_SET.lock().add(socket);
                SOCKETS_TYPE_MAP.lock().insert(handle, SocketType::Udpv6);

                let fd = socket_alloc_fd_net();

                SOCKETS.lock().get_mut(&pid).unwrap().insert(fd, handle);

                return fd;
            }
            _ => -(EINVAL as i32),
        },
        _ => -(EINVAL as i32),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_shutdown(fd: u64, how: u64) -> u64 {
    let mut sockets = SOCKETS.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.remove(&(fd as i32)) {
        return 0;
    }

    (-(EBADF as i64)) as u64
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_getpeername(
    fd: u64,
    addr: *mut sockaddr_un,
    addrlen: *mut socklen_t,
) -> u64 {
    let mut sockets = SOCKETS.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {}

    (-(EBADF as i64)) as u64
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct sockaddr_in6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_bind(fd: u64, addr: *const sockaddr_un, addrlen: socklen_t) -> i32 {
    let mut sockets = SOCKETS.lock();
    let mut socket_sets = SOCKETS_SET.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
        if let SocketType::Udpv4 = *SOCKETS_TYPE_MAP.lock().get(&*socket).unwrap() {
            let udp_socket: &mut smoltcp::socket::udp::Socket = socket_sets.get_mut(*socket);
            if let Some(addr) = unsafe { (addr as *const sockaddr_in).as_ref() } {
                let ip_endpoint = IpEndpoint::new(
                    smoltcp::wire::IpAddress::Ipv4(Ipv4Addr::from_octets(addr.sin_addr)),
                    addr.sin_port,
                );
                let _ = udp_socket.bind(ip_endpoint);
                return 0;
            }
        } else if let SocketType::Udpv6 = *SOCKETS_TYPE_MAP.lock().get(&*socket).unwrap() {
            let udp_socket: &mut smoltcp::socket::udp::Socket = socket_sets.get_mut(*socket);
            if let Some(addr) = unsafe { (addr as *const sockaddr_in6).as_ref() } {
                let ip_endpoint = IpEndpoint::new(
                    smoltcp::wire::IpAddress::Ipv6(Ipv6Addr::from_octets(addr.sin6_addr)),
                    addr.sin6_port,
                );
                let _ = udp_socket.bind(ip_endpoint);
                return 0;
            }
        }
    }

    -(EBADF as i32)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_listen(fd: u64, backlog: i32) -> i32 {
    let mut sockets = SOCKETS.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {}

    -(EBADF as i32)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_accept(fd: u64, addr: *mut sockaddr_un, addrlen: *mut socklen_t) -> i32 {
    let mut sockets = SOCKETS.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };
    if let Some(socket) = queue.get_mut(&(fd as i32)) {}

    -(EBADF as i32)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_connect(fd: u64, addr: *const sockaddr_un, addrlen: socklen_t) -> i32 {
    let mut sockets = SOCKETS.lock();
    let mut socket_sets = SOCKETS_SET.lock();

    let pid: usize = {
        let task = unsafe { arch_get_current() };
        unsafe { *task }.pid as usize
    };

    let queue = { sockets.get_mut(&pid).unwrap() };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
        if let SocketType::Udpv4 = *SOCKETS_TYPE_MAP.lock().get(&*socket).unwrap() {
            let udp_socket: &mut smoltcp::socket::udp::Socket = socket_sets.get_mut(*socket);
            if let Some(addr) = unsafe { (addr as *const sockaddr_in).as_ref() } {
                let ip_endpoint = IpEndpoint::new(
                    smoltcp::wire::IpAddress::Ipv4(Ipv4Addr::from_octets(addr.sin_addr)),
                    addr.sin_port,
                );

                if let Some(queue) = SOCKETS_UDP_CONNECTIONS.lock().get_mut(&pid) {
                    queue.insert(fd as i32, ip_endpoint);
                }

                return 0;
            }
        } else if let SocketType::Udpv6 = *SOCKETS_TYPE_MAP.lock().get(&*socket).unwrap() {
            let udp_socket: &mut smoltcp::socket::udp::Socket = socket_sets.get_mut(*socket);
            if let Some(addr) = unsafe { (addr as *const sockaddr_in6).as_ref() } {
                let ip_endpoint = IpEndpoint::new(
                    smoltcp::wire::IpAddress::Ipv6(Ipv6Addr::from_octets(addr.sin6_addr)),
                    addr.sin6_port,
                );

                if let Some(queue) = SOCKETS_UDP_CONNECTIONS.lock().get_mut(&pid) {
                    queue.insert(fd as i32, ip_endpoint);
                }

                return 0;
            }
        }
    }

    -(EBADF as i32)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_sendto(
    fd: u64,
    inaddr: *const u8,
    limit: u64,
    flags: i32,
    addr: *mut sockaddr_un,
    len: u32,
) -> u64 {
    let mut sockets_set = SOCKETS_SET.lock();
    let sockets_type_map = SOCKETS_TYPE_MAP.lock();
    let mut sockets = SOCKETS.lock();

    let pid = {
        let task = unsafe { arch_get_current() };
        unsafe { *task }.pid as usize
    };

    let queue = { sockets.get_mut(&pid).unwrap() };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
        if *sockets_type_map.get(&*socket).unwrap() == SocketType::Rawv4
            || *sockets_type_map.get(&*socket).unwrap() == SocketType::Rawv6
        {
            let raw: &mut raw::Socket = sockets_set.get_mut(*socket);
            if let Err(err) =
                raw.send_slice(unsafe { core::slice::from_raw_parts(inaddr, limit as usize) })
            {
                match err {
                    raw::SendError::BufferFull => return (-(EBUSY as i64)) as u64,
                }
            }
            return limit as u64;
        } else if let SocketType::Udpv4 = *sockets_type_map.get(&*socket).unwrap() {
            let udp_socket: &mut smoltcp::socket::udp::Socket = sockets_set.get_mut(*socket);
            if let Some(addr) = unsafe { (addr as *const sockaddr_in).as_ref() } {
                let ip_endpoint = IpEndpoint::new(
                    smoltcp::wire::IpAddress::Ipv4(Ipv4Addr::from_octets(addr.sin_addr)),
                    addr.sin_port,
                );

                if udp_socket.endpoint().port == 0 {
                    let _ = udp_socket.bind(IpEndpoint::new(
                        smoltcp::wire::IpAddress::Ipv4(Ipv4Addr::UNSPECIFIED),
                        65522,
                    ));
                }

                let res = udp_socket.send_slice(
                    unsafe { core::slice::from_raw_parts(inaddr, limit as usize) },
                    UdpMetadata::from(ip_endpoint),
                );

                if let Err(_) = res {
                    return (-(EINVAL as i64)) as u64;
                }

                return limit;
            }
        } else if let SocketType::Udpv6 = *sockets_type_map.get(&*socket).unwrap() {
            let udp_socket: &mut smoltcp::socket::udp::Socket = sockets_set.get_mut(*socket);
            if let Some(addr) = unsafe { (addr as *const sockaddr_in6).as_ref() } {
                let ip_endpoint = IpEndpoint::new(
                    smoltcp::wire::IpAddress::Ipv6(Ipv6Addr::from_octets(addr.sin6_addr)),
                    addr.sin6_port,
                );

                if udp_socket.endpoint().port == 0 {
                    let _ = udp_socket.bind(IpEndpoint::new(
                        smoltcp::wire::IpAddress::Ipv4(Ipv4Addr::UNSPECIFIED),
                        65522,
                    ));
                }

                let res = udp_socket.send_slice(
                    unsafe { core::slice::from_raw_parts(inaddr, limit as usize) },
                    UdpMetadata::from(ip_endpoint),
                );

                if let Err(_) = res {
                    return (-(EINVAL as i64)) as u64;
                }

                return limit;
            }
        }
    }

    (-(EBADF as i64)) as u64
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_recvfrom(
    fd: u64,
    out: *mut u8,
    limit: u64,
    flags: i32,
    addr: *mut sockaddr_un,
    len: *mut u32,
) -> u64 {
    let mut sockets_set = SOCKETS_SET.lock();
    let sockets_type_map = SOCKETS_TYPE_MAP.lock();
    let mut sockets = SOCKETS.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
        if *sockets_type_map.get(&*socket).unwrap() == SocketType::Rawv4
            || *sockets_type_map.get(&*socket).unwrap() == SocketType::Rawv6
        {
            let raw: &mut raw::Socket = sockets_set.get_mut(*socket);
            if let Err(err) =
                raw.recv_slice(unsafe { core::slice::from_raw_parts_mut(out, limit as usize) })
            {
                match err {
                    raw::RecvError::Exhausted => return 0,
                    raw::RecvError::Truncated => return (-(EMSGSIZE as i64)) as u64,
                }
            }
            return limit as u64;
        } else if let SocketType::Udpv4 = *sockets_type_map.get(&*socket).unwrap() {
            let udp_socket: &mut smoltcp::socket::udp::Socket = sockets_set.get_mut(*socket);
            let res = udp_socket
                .recv_slice(unsafe { core::slice::from_raw_parts_mut(out, limit as usize) });

            if let Err(_) = res {
                return (-(ENODATA as i64)) as u64;
            }

            return limit;
        } else if let SocketType::Udpv6 = *sockets_type_map.get(&*socket).unwrap() {
            let udp_socket: &mut smoltcp::socket::udp::Socket = sockets_set.get_mut(*socket);
            let res = udp_socket
                .recv_slice(unsafe { core::slice::from_raw_parts_mut(out, limit as usize) });

            if let Err(_) = res {
                return (-(ENODATA as i64)) as u64;
            }

            return limit;
        }
    }

    (-(EBADF as i64)) as u64
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_getsockopt(
    fd: u64,
    level: i32,
    optname: i32,
    optval: *const core::ffi::c_void,
    optlen: *mut u64,
) -> u64 {
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_setsockopt(
    fd: u64,
    level: i32,
    optname: i32,
    optval: *const core::ffi::c_void,
    optlen: u64,
) -> u64 {
    0
}
