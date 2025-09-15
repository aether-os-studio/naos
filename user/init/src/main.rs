fn main() {
    println!("aether-init is running...");

    unsafe { std::env::set_var("PATH", "/usr/local/bin:/usr/bin:/bin") };

    println!("init: Starting seatd");
    let seatd = unsafe { libc::fork() };
    if seatd == 0 {
        unsafe {
            libc::execl(
                b"/usr/bin/seatd\0".as_ptr() as *const _,
                b"seatd\0".as_ptr() as *const _,
                core::ptr::null::<core::ffi::c_char>(),
            )
        };
        panic!("Failed to exec seatd");
    } else {
        assert_ne!(seatd, -1);
    }

    // if unsafe { libc::access(b"/etc/udev/hwdb.bin".as_ptr() as *const _, libc::F_OK) } != 0 {
    //     println!("init: Generating hwdb");
    //     let hwdb = unsafe { libc::fork() };
    //     if hwdb == 0 {
    //         unsafe {
    //             libc::execl(
    //                 b"/sbin/udevadm\0".as_ptr() as *const _,
    //                 b"udevadm\0".as_ptr() as *const _,
    //                 b"hwdb\0".as_ptr() as *const _,
    //                 b"--update\0".as_ptr() as *const _,
    //                 core::ptr::null::<core::ffi::c_char>(),
    //             )
    //         };
    //         panic!("Failed to exec udevadm hwdb --update");
    //     } else {
    //         assert_ne!(hwdb, -1);
    //     }

    //     unsafe { libc::waitpid(hwdb, core::ptr::null_mut(), 0) };
    // } else {
    //     println!("init: hwdb already exists, skipping generation");
    // }

    // println!("init: Starting udev");
    // let udev = unsafe { libc::fork() };
    // if udev == 0 {
    //     unsafe {
    //         libc::execl(
    //             b"/sbin/udevd\0".as_ptr() as *const _,
    //             b"udevd\0".as_ptr() as *const _,
    //             // b"--debug\0".as_ptr() as *const _,
    //             core::ptr::null::<core::ffi::c_char>(),
    //         )
    //     };
    //     panic!("Failed to exec udevd");
    // } else {
    //     assert_ne!(udev, -1);
    // }

    // while unsafe { libc::access(b"/run/udev/control\0".as_ptr() as *const _, libc::F_OK) } != 0 {
    //     // wait for /run/udev/control to appear
    //     std::thread::sleep(std::time::Duration::from_millis(1000));
    // }

    // println!("init: Running udev-trigger");
    // let udev_trigger = unsafe { libc::fork() };
    // if udev_trigger == 0 {
    //     unsafe {
    //         libc::execl(
    //             b"/sbin/udevadm\0".as_ptr() as *const _,
    //             b"udevadm\0".as_ptr() as *const _,
    //             b"trigger\0".as_ptr() as *const _,
    //             b"--action=add\0".as_ptr() as *const _,
    //             core::ptr::null::<core::ffi::c_char>(),
    //         )
    //     };
    //     panic!("Failed to exec udev-trigger");
    // } else {
    //     assert_ne!(udev_trigger, -1);
    // }

    // unsafe { libc::waitpid(udev_trigger, core::ptr::null_mut(), 0) };

    // println!("init: Running udev-settle");
    // let udev_settle = unsafe { libc::fork() };
    // if udev_settle == 0 {
    //     unsafe {
    //         libc::execl(
    //             b"/sbin/udevadm\0".as_ptr() as *const _,
    //             b"udevadm\0".as_ptr() as *const _,
    //             b"settle\0".as_ptr() as *const _,
    //             core::ptr::null::<core::ffi::c_char>(),
    //         )
    //     };
    //     panic!("Failed to exec udev-settle");
    // } else {
    //     assert_ne!(udev_settle, -1);
    // }

    // unsafe { libc::waitpid(udev_settle, core::ptr::null_mut(), 0) };

    // let mut need_keyboard = true;
    // let mut need_mouse = true;

    // println!("init: Waiting for keyboard and mouse");

    // while need_keyboard || need_mouse {
    //     if unsafe { libc::access(b"/run/udev/data/c13:0\0".as_ptr() as *const _, libc::F_OK) } == 0
    //     {
    //         need_keyboard = false;
    //     }
    //     if unsafe { libc::access(b"/run/udev/data/c13:1\0".as_ptr() as *const _, libc::F_OK) } == 0
    //     {
    //         need_mouse = false;
    //     }
    //     std::thread::sleep(std::time::Duration::from_millis(1000));
    // }

    // println!("init: Found keyboard and mouse");

    unsafe {
        libc::open(
            b"/run/udev/data/c13:0\0".as_ptr() as *const _,
            libc::O_CREAT,
            0,
        )
    };
    unsafe {
        libc::open(
            b"/run/udev/data/c13:1\0".as_ptr() as *const _,
            libc::O_CREAT,
            0,
        )
    };

    println!("init: Starting desktop process");
    let desktop = unsafe { libc::fork() };
    if desktop == 0 {
        unsafe {
            std::env::set_var("HOME", "/root");
            std::env::set_var("XDG_RUNTIME_DIR", "/run");
            std::env::set_var("SHELL", "/bin/bash");
            std::env::set_var("MESA_SHADER_CACHE_DISABLE", "1");
            // std::env::set_var("WESTON_LIBINPUT_LOG_PRIORITY", "debug");
        }

        unsafe {
            libc::execl(
                b"/usr/bin/weston\0".as_ptr() as *const _,
                b"weston\0".as_ptr() as *const _,
                b"--xwayland\0".as_ptr() as *const _,
                core::ptr::null::<core::ffi::c_char>(),
            )
        };
        panic!("Failed to exec desktop process");
    } else {
        assert_ne!(desktop, -1);
    }

    let mut status: i32 = 0;
    unsafe { libc::waitpid(desktop, &mut status as *mut i32, 0) };

    println!("init: desktop process exited with status: {}", status);

    #[allow(unused)]
    #[derive(Default)]
    #[repr(C)]
    struct VtMode {
        pub mode: u8,    // 终端模式
        pub waitv: u8,   // 垂直同步
        pub relsig: u16, // 释放信号
        pub acqsig: u16, // 获取信号
        pub frsig: u16,  // 强制释放信号
    }

    let mut vt: VtMode = VtMode::default();
    unsafe {
        libc::ioctl(1, 0x5601, &mut vt as *mut _);
        vt.mode = 0;
        libc::ioctl(1, 0x5602, &mut vt as *mut _);
    }

    println!("init: Starting shell");
    let shell = unsafe { libc::fork() };
    if shell == 0 {
        unsafe {
            libc::execl(
                b"/bin/bash\0".as_ptr() as *const _,
                b"bash\0".as_ptr() as *const _,
                core::ptr::null::<core::ffi::c_char>(),
            )
        };
        panic!("Failed to exec shell");
    } else {
        assert_ne!(shell, -1);
    }

    let mut status: i32 = 0;
    unsafe { libc::waitpid(shell, &mut status as *mut i32, 0) };

    println!("init: shell exited with status: {}", status);
}
