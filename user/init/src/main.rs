fn main() {
    println!("aether-init is running...");

    println!("init: Starting seatd");
    let seatd = unsafe { libc::fork() };
    if seatd == 0 {
        unsafe {
            libc::execl(
                b"/usr/bin/seatd\0".as_ptr() as *const _,
                b"seatd\0".as_ptr() as *const _,
            )
        };
    } else {
        assert_ne!(seatd, -1);
    }

    println!("init: Starting udev");
    let udev = unsafe { libc::fork() };
    if udev == 0 {
        unsafe {
            libc::execl(
                b"/sbin/udevd\0".as_ptr() as *const _,
                b"udevd\0".as_ptr() as *const _,
            )
        };
    } else {
        assert_ne!(udev, -1);
    }

    while (unsafe { libc::access(b"/run/udev/control\0".as_ptr() as *const _, libc::F_OK) }) != 0 {
        // wait for /run/udev/control to appear
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    // println!("init: Running udev-trigger");
    // let udev_trigger = unsafe { libc::fork() };
    // if udev_trigger == 0 {
    //     unsafe {
    //         libc::execl(
    //             b"/sbin/udev-trigger\0".as_ptr() as *const _,
    //             b"udev-trigger\0".as_ptr() as *const _,
    //         )
    //     };
    // } else {
    //     assert_ne!(udev_trigger, -1);
    // }

    // unsafe { libc::waitpid(udev_trigger, core::ptr::null_mut(), 0) };

    // println!("init: Running udev-settle");
    // let udev_settle = unsafe { libc::fork() };
    // if udev_settle == 0 {
    //     unsafe {
    //         libc::execl(
    //             b"/sbin/udev-settle\0".as_ptr() as *const _,
    //             b"udev-settle\0".as_ptr() as *const _,
    //         )
    //     };
    // } else {
    //     assert_ne!(udev_settle, -1);
    // }

    // unsafe { libc::waitpid(udev_settle, core::ptr::null_mut(), 0) };

    // let mut need_keyboard = true;
    // let mut need_mouse = true;

    // let _init_udev = udev::Udev::new().unwrap();

    // let init_udev_mon = udev::MonitorBuilder::new().unwrap();

    // while need_keyboard || need_mouse {
    //     let socket = init_udev_mon
    //         .clone()
    //         .match_subsystem("input")
    //         .unwrap()
    //         .listen()
    //         .unwrap();

    //     for event in socket.iter() {
    //         let syspath = event.syspath();
    //         println!("init: udev event syspath: {:?}", syspath);
    //         let subsystem = event.subsystem().unwrap();

    //         if subsystem.eq("input") {
    //             if event.property_value("ID_INPUT_KEYBOARD").is_some() {
    //                 println!("init: Found keyboard");
    //                 need_keyboard = false;
    //             }
    //             if event.property_value("ID_INPUT_MOUSE").is_some() {
    //                 println!("init: Found mouse");
    //                 need_mouse = false;
    //             }
    //         }
    //     }
    // }

    println!("init: Starting weston");
    let weston = unsafe { libc::fork() };
    if weston == 0 {
        unsafe {
            std::env::set_var("HOME", "/root");
            std::env::set_var("XDG_RUNTIME_DIR", "/run");
            std::env::set_var("SHELL", "/bin/bash");
            std::env::set_var("MESA_SHADER_CACHE_DISABLE", "1");
        }

        unsafe {
            libc::execl(
                b"/usr/bin/weston\0".as_ptr() as *const _,
                b"weston\0".as_ptr() as *const _,
            )
        };
    } else {
        assert_ne!(weston, -1);
    }

    let mut status: i32 = 0;
    unsafe { libc::waitpid(weston, &mut status as *mut i32, 0) };

    println!("init: Weston exited with status: {}", status);
}
