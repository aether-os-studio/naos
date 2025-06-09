use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{AnySocket, Socket, raw},
    storage::{PacketBuffer, PacketMetadata},
    wire::{IpProtocol, IpVersion},
};
use spin::{Lazy, Mutex};

use crate::rust::bindings::bindings::*;

pub trait NetworkDevice: Send + Sync {
    fn poll(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SocketType {
    Raw,
    Tcp,
    Udp,
}

pub static SOCKETS_SET: Lazy<Mutex<SocketSet>> =
    Lazy::new(|| Mutex::new(SocketSet::new(Vec::new())));
pub static SOCKETS_TYPE_MAP: Mutex<BTreeMap<SocketHandle, SocketType>> =
    Mutex::new(BTreeMap::new());
pub static SOCKETS: Mutex<BTreeMap<usize, BTreeMap<i32, SocketHandle>>> =
    Mutex::new(BTreeMap::new());
pub static SOCKETS_DUPS: Mutex<BTreeMap<usize, BTreeMap<i32, usize>>> = Mutex::new(BTreeMap::new());

#[unsafe(no_mangle)]
unsafe extern "C" fn socket_on_new_task(pid: usize) {
    SOCKETS.lock().insert(pid, BTreeMap::new());
    SOCKETS_DUPS.lock().insert(pid, BTreeMap::new());
}
#[unsafe(no_mangle)]
unsafe extern "C" fn socket_on_exit_task(pid: usize) {
    let queue = SOCKETS.lock().remove(&pid).unwrap();
    for (_, handle) in queue {
        SOCKETS_SET.lock().remove(handle);
    }
    let _ = SOCKETS_DUPS.lock().remove(&pid);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn socket_on_dup_file(fd: usize, newfd: usize) {
    let mut sockets = SOCKETS_DUPS.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    queue.insert(newfd as i32, fd);
}

const RAW_BUFFER_SIZE: usize = 1536;

unsafe extern "C" {
    fn socket_alloc_fd_net() -> i32;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_socket(domain: i32, ty: i32, protocol: i32) -> i32 {
    let mut rx_1 = Vec::new();
    (0..RAW_BUFFER_SIZE).for_each(|_| rx_1.push(PacketMetadata::EMPTY));
    let mut rx_2 = Vec::new();
    (0..RAW_BUFFER_SIZE).for_each(|_| rx_2.push(0));

    let rx = PacketBuffer::new(rx_1, rx_2);

    let mut tx_1 = Vec::new();
    (0..RAW_BUFFER_SIZE).for_each(|_| tx_1.push(PacketMetadata::EMPTY));
    let mut tx_2 = Vec::new();
    (0..RAW_BUFFER_SIZE).for_each(|_| tx_2.push(0));
    let tx = PacketBuffer::new(tx_1, tx_2);

    let pid = {
        let task = unsafe { arch_get_current() };
        unsafe { *task }.pid as usize
    };

    match domain {
        // AF_INET
        2 => match ty {
            // RAW
            3 => {
                let socket =
                    raw::Socket::new(IpVersion::Ipv4, IpProtocol::from(protocol as u8), rx, tx);

                let handle = SOCKETS_SET.lock().add(socket);
                SOCKETS_TYPE_MAP.lock().insert(handle, SocketType::Raw);

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
                let socket =
                    raw::Socket::new(IpVersion::Ipv6, IpProtocol::from(protocol as u8), rx, tx);

                let handle = SOCKETS_SET.lock().add(socket);
                SOCKETS_TYPE_MAP.lock().insert(handle, SocketType::Raw);

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

    let mut all_dupfds = SOCKETS_DUPS.lock();

    let dupfds = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        all_dupfds.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.remove(&(fd as i32)) {
        return 0;
    } else if let Some(dupfd) = dupfds.remove(&(fd as i32)) {
        if let Some(socket) = queue.remove(&(fd as i32)) {
            return 0;
        }
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

    let mut all_dupfds = SOCKETS_DUPS.lock();

    let dupfds = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        all_dupfds.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
    } else if let Some(&dupfd) = dupfds.get(&(fd as i32)) {
        if let Some(socket) = queue.get_mut(&(dupfd as i32)) {}
    }

    (-(EBADF as i64)) as u64
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_bind(fd: u64, addr: *const sockaddr_un, addrlen: socklen_t) -> i32 {
    let mut sockets = SOCKETS.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    let mut all_dupfds = SOCKETS_DUPS.lock();

    let dupfds = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        all_dupfds.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
    } else if let Some(&dupfd) = dupfds.get(&(fd as i32)) {
        if let Some(socket) = queue.get_mut(&(dupfd as i32)) {}
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

    let mut all_dupfds = SOCKETS_DUPS.lock();

    let dupfds = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        all_dupfds.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
    } else if let Some(&dupfd) = dupfds.get(&(fd as i32)) {
        if let Some(socket) = queue.get_mut(&(dupfd as i32)) {}
    }

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

    let mut all_dupfds = SOCKETS_DUPS.lock();

    let dupfds = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        all_dupfds.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
    } else if let Some(&dupfd) = dupfds.get(&(fd as i32)) {
        if let Some(socket) = queue.get_mut(&(dupfd as i32)) {}
    }

    -(EBADF as i32)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn net_connect(fd: u64, addr: *const sockaddr_un, addrlen: socklen_t) -> i32 {
    let mut sockets = SOCKETS.lock();

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    let mut all_dupfds = SOCKETS_DUPS.lock();

    let dupfds = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        all_dupfds.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
    } else if let Some(&dupfd) = dupfds.get(&(fd as i32)) {
        if let Some(socket) = queue.get_mut(&(dupfd as i32)) {}
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

    let queue = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        sockets.get_mut(&pid).unwrap()
    };

    let mut all_dupfds = SOCKETS_DUPS.lock();

    let dupfds = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        all_dupfds.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
        if *sockets_type_map.get(&*socket).unwrap() == SocketType::Raw {
            let raw: &mut raw::Socket = sockets_set.get_mut(*socket);
            if let Err(err) =
                raw.send_slice(unsafe { core::slice::from_raw_parts(inaddr, limit as usize) })
            {
                match err {
                    raw::SendError::BufferFull => return (-(EBUSY as i64)) as u64,
                }
            }
            return limit as u64;
        }
    } else if let Some(&dupfd) = dupfds.get(&(fd as i32)) {
        if let Some(socket) = queue.get_mut(&(dupfd as i32)) {
            if *sockets_type_map.get(&*socket).unwrap() == SocketType::Raw {
                let raw: &mut raw::Socket = sockets_set.get_mut(*socket);
                if let Err(err) =
                    raw.send_slice(unsafe { core::slice::from_raw_parts(inaddr, limit as usize) })
                {
                    match err {
                        raw::SendError::BufferFull => return (-(EBUSY as i64)) as u64,
                    }
                }
                return limit as u64;
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

    let mut all_dupfds = SOCKETS_DUPS.lock();

    let dupfds = {
        let pid = {
            let task = unsafe { arch_get_current() };
            unsafe { *task }.pid as usize
        };
        all_dupfds.get_mut(&pid).unwrap()
    };

    if let Some(socket) = queue.get_mut(&(fd as i32)) {
        if *sockets_type_map.get(&*socket).unwrap() == SocketType::Raw {
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
        }
    } else if let Some(&dupfd) = dupfds.get(&(fd as i32)) {
        if let Some(socket) = queue.get_mut(&(dupfd as i32)) {
            if *sockets_type_map.get(&*socket).unwrap() == SocketType::Raw {
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
            }
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
