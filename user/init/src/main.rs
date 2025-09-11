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

    // println!("init: Starting dbus");
    // let dbus = unsafe { libc::fork() };
    // if dbus == 0 {
    //     unsafe {
    //         libc::execl(
    //             b"/usr/bin/dbus-daemon\0".as_ptr() as *const _,
    //             b"dbus-daemon\0".as_ptr() as *const _,
    //             b"--system\0".as_ptr() as *const _,
    //         )
    //     };
    // } else {
    //     assert_ne!(dbus, -1);
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
