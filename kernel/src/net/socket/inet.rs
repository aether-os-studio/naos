use core::{ffi::c_void, sync::atomic::AtomicI32};

use alloc::{boxed::Box, collections::btree_map::BTreeMap};
use smoltcp::{
    iface::{Context, SocketHandle},
    socket::{AnySocket, tcp::SocketBuffer},
    storage::{PacketBuffer, PacketMetadata},
    wire::{IpEndpoint, Ipv4Address},
};
use spin::Mutex;

use crate::{
    net::{
        net_core::SOCKET_SET,
        netdev::{DEFAULT_NETDEV, IPV4_ADDR},
    },
    rust::bindings::bindings::{
        EADDRNOTAVAIL, EBADF, EINVAL, EIO, ENOTCONN, EPOLLIN, EPOLLOUT, sockaddr_in,
    },
};

pub enum SocketHandleType {
    Tcp,
    Udp,
    Raw,
}

pub static SMOLTCP_FD_NEXT: AtomicI32 = AtomicI32::new(1);

pub static SMOLTCP_FDS: Mutex<BTreeMap<i32, SocketHandle>> = Mutex::new(BTreeMap::new());
pub static SMOLTCP_FDS_TYPES: Mutex<BTreeMap<i32, SocketHandleType>> = Mutex::new(BTreeMap::new());

#[unsafe(no_mangle)]
extern "C" fn smoltcp_poll(smoltcp_fd: i32, events: u32) -> i32 {
    let socket_types = SMOLTCP_FDS_TYPES.lock();

    let mut socket_set = SOCKET_SET.lock();

    let mut revents: i32 = 0;

    let ty = socket_types.get(&smoltcp_fd);
    if let Some(ty) = ty {
        match ty {
            SocketHandleType::Tcp => {
                let socket: &mut smoltcp::socket::tcp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if (events & EPOLLIN) != 0 && socket.can_recv() {
                    revents |= EPOLLIN as i32;
                }
                if (events & EPOLLOUT) != 0 && socket.can_send() {
                    revents |= EPOLLOUT as i32
                }

                return revents;
            }
            SocketHandleType::Udp => {
                let socket: &mut smoltcp::socket::udp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if (events & EPOLLIN) != 0 && socket.can_recv() {
                    revents |= EPOLLIN as i32;
                }
                if (events & EPOLLOUT) != 0 && socket.can_send() {
                    revents |= EPOLLOUT as i32;
                }

                return revents;
            }
            SocketHandleType::Raw => {
                let socket: &mut smoltcp::socket::raw::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if (events & EPOLLIN) != 0 && socket.can_recv() {
                    revents |= EPOLLIN as i32;
                }
                if (events & EPOLLOUT) != 0 && socket.can_send() {
                    revents |= EPOLLOUT as i32;
                }

                return revents;
            }
        }
    }
    return -(EBADF as i32);
}

#[unsafe(no_mangle)]
extern "C" fn smoltcp_getsockname(smoltcp_fd: i32, addr: *mut c_void, addrlen: *mut u32) -> i32 {
    let addr = addr as *mut sockaddr_in;

    let socket_types = SMOLTCP_FDS_TYPES.lock();

    let mut socket_set = SOCKET_SET.lock();

    let ty = socket_types.get(&smoltcp_fd);
    if let Some(ty) = ty {
        match ty {
            SocketHandleType::Tcp => {
                let socket: &mut smoltcp::socket::tcp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if let Some(endpoint) = socket.remote_endpoint() {
                    let bytes = endpoint.addr.as_bytes();
                    unsafe { *addr }.sin_addr.copy_from_slice(bytes);
                    unsafe { *addr }.sin_port = endpoint.port;
                }

                return 0;
            }
            SocketHandleType::Udp => {
                let socket: &mut smoltcp::socket::udp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                let endpoint = socket.endpoint();
                if let Some(ep_addr) = endpoint.addr {
                    let ep_addr = ep_addr.as_bytes();
                    let mut sock_addr = sockaddr_in {
                        sin_family: 0,
                        sin_port: 0,
                        sin_addr: [0u8; 4],
                        sin_zero: [0u8; 8],
                    };
                    sock_addr.sin_addr.copy_from_slice(ep_addr);
                    sock_addr.sin_port = endpoint.port;
                    unsafe { *addr = sock_addr };
                    return 0;
                } else {
                    return -(ENOTCONN as i32);
                }
            }
            SocketHandleType::Raw => {
                let socket: &mut smoltcp::socket::raw::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                return 0;
            }
        }
    }
    return -(EBADF as i32);
}

#[unsafe(no_mangle)]
extern "C" fn smoltcp_connect(smoltcp_fd: i32, addr: *const c_void, addrlen: u32) -> i32 {
    let addr = unsafe { *(addr as *const sockaddr_in) };

    let socket_types = SMOLTCP_FDS_TYPES.lock();

    let mut socket_set = SOCKET_SET.lock();

    let ty = socket_types.get(&smoltcp_fd);
    if let Some(ty) = ty {
        match ty {
            SocketHandleType::Tcp => {
                let socket: &mut smoltcp::socket::tcp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());
                if let Err(e) = socket.connect(
                    DEFAULT_NETDEV.lock().iface.lock().context(),
                    IpEndpoint::new(
                        smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(&addr.sin_addr)),
                        addr.sin_port,
                    ),
                    IpEndpoint::new(
                        smoltcp::wire::IpAddress::Ipv4(IPV4_ADDR.lock().unwrap().address()),
                        addr.sin_port,
                    ),
                ) {
                    match e {
                        smoltcp::socket::tcp::ConnectError::InvalidState => {
                            return -(EINVAL as i32);
                        }
                        smoltcp::socket::tcp::ConnectError::Unaddressable => {
                            return -(EADDRNOTAVAIL as i32);
                        }
                    }
                } else {
                    return 0;
                }
            }
            SocketHandleType::Udp => {
                let socket: &mut smoltcp::socket::udp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                let _res = socket.bind(IpEndpoint::new(
                    smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(&addr.sin_addr)),
                    addr.sin_port,
                ));

                return 0;
            }
            SocketHandleType::Raw => {
                let _socket: &mut smoltcp::socket::raw::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                return 0;
            }
        }
    }
    return -(EBADF as i32);
}

#[unsafe(no_mangle)]
extern "C" fn smoltcp_sendto(
    smoltcp_fd: i32,
    buffer: *const c_void,
    limit: usize,
    flags: i32,
    addr: *const c_void,
    len: u32,
) -> i32 {
    let addr = unsafe { *(addr as *const sockaddr_in) };

    let socket_types = SMOLTCP_FDS_TYPES.lock();

    let mut socket_set = SOCKET_SET.lock();

    let ty = socket_types.get(&smoltcp_fd);
    if let Some(ty) = ty {
        match ty {
            SocketHandleType::Tcp => {
                let socket: &mut smoltcp::socket::tcp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if let Ok(res) = socket
                    .send_slice(unsafe { core::slice::from_raw_parts(buffer as *const u8, limit) })
                {
                    return res as i32;
                } else {
                    return -(EIO as i32);
                }
            }
            SocketHandleType::Udp => {
                let socket: &mut smoltcp::socket::udp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if let Ok(_) = socket.send_slice(
                    unsafe { core::slice::from_raw_parts(buffer as *const u8, limit) },
                    IpEndpoint::new(
                        smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(&addr.sin_addr)),
                        addr.sin_port,
                    ),
                ) {
                    return limit as i32;
                } else {
                    return -(EIO as i32);
                }
            }
            SocketHandleType::Raw => {
                let socket: &mut smoltcp::socket::raw::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if let Ok(_) = socket
                    .send_slice(unsafe { core::slice::from_raw_parts(buffer as *const u8, limit) })
                {
                    return limit as i32;
                } else {
                    return -(EIO as i32);
                }
            }
        }
    }
    return -(EBADF as i32);
}

#[unsafe(no_mangle)]
extern "C" fn smoltcp_recvfrom(
    smoltcp_fd: i32,
    buffer: *mut c_void,
    limit: usize,
    flags: i32,
    addr: *mut c_void,
    len: *mut u32,
) -> i32 {
    let socket_types = SMOLTCP_FDS_TYPES.lock();

    let mut socket_set = SOCKET_SET.lock();

    let ty = socket_types.get(&smoltcp_fd);
    if let Some(ty) = ty {
        match ty {
            SocketHandleType::Tcp => {
                let socket: &mut smoltcp::socket::tcp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if let Ok(res) = socket.recv_slice(unsafe {
                    core::slice::from_raw_parts_mut(buffer as *mut u8, limit)
                }) {
                    return res as i32;
                } else {
                    return -(EIO as i32);
                }
            }
            SocketHandleType::Udp => {
                let socket: &mut smoltcp::socket::udp::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if let Ok(_) = socket.recv_slice(unsafe {
                    core::slice::from_raw_parts_mut(buffer as *mut u8, limit)
                }) {
                    return limit as i32;
                } else {
                    return -(EIO as i32);
                }
            }
            SocketHandleType::Raw => {
                let socket: &mut smoltcp::socket::raw::Socket =
                    socket_set.get_mut(*SMOLTCP_FDS.lock().get(&smoltcp_fd).unwrap());

                if let Ok(_) = socket.recv_slice(unsafe {
                    core::slice::from_raw_parts_mut(buffer as *mut u8, limit)
                }) {
                    return limit as i32;
                } else {
                    return -(EIO as i32);
                }
            }
        }
    }
    return -(EBADF as i32);
}

#[unsafe(no_mangle)]
extern "C" fn smoltcp_socket(domain: i32, ty: i32, protocol: i32) -> i32 {
    let smoltcp_fd = SMOLTCP_FD_NEXT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);

    let socket_handle = match domain {
        2 => match ty {
            1 => {
                // Stream
                let rx_buffer = SocketBuffer::new(alloc::vec![0u8; 4096]);
                let tx_buffer = SocketBuffer::new(alloc::vec![0u8; 4096]);
                let socket = smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);
                SMOLTCP_FDS_TYPES
                    .lock()
                    .insert(smoltcp_fd, SocketHandleType::Tcp);
                SOCKET_SET.lock().add(socket)
            }
            2 => {
                // Datagram
                let rx_buffer = PacketBuffer::new(
                    alloc::vec![PacketMetadata::EMPTY; 4096],
                    alloc::vec![0u8; 4096],
                );
                let tx_buffer = PacketBuffer::new(
                    alloc::vec![PacketMetadata::EMPTY; 4096],
                    alloc::vec![0u8; 4096],
                );
                let socket = smoltcp::socket::udp::Socket::new(rx_buffer, tx_buffer);
                SMOLTCP_FDS_TYPES
                    .lock()
                    .insert(smoltcp_fd, SocketHandleType::Udp);
                SOCKET_SET.lock().add(socket)
            }
            3 => {
                // Raw
                let rx_buffer = PacketBuffer::new(
                    alloc::vec![PacketMetadata::EMPTY; 4096],
                    alloc::vec![0u8; 4096],
                );
                let tx_buffer = PacketBuffer::new(
                    alloc::vec![PacketMetadata::EMPTY; 4096],
                    alloc::vec![0u8; 4096],
                );
                let socket = smoltcp::socket::raw::Socket::new(
                    smoltcp::wire::IpVersion::Ipv4,
                    smoltcp::wire::IpProtocol::from(protocol as u8),
                    rx_buffer,
                    tx_buffer,
                );
                SMOLTCP_FDS_TYPES
                    .lock()
                    .insert(smoltcp_fd, SocketHandleType::Raw);
                SOCKET_SET.lock().add(socket)
            }
            _ => return -(EINVAL as i32),
        },
        _ => return -(EINVAL as i32),
    };

    SMOLTCP_FDS.lock().insert(smoltcp_fd, socket_handle);

    smoltcp_fd
}
