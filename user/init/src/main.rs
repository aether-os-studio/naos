use std::{fs::File, io::Read};

fn main() {
    println!("aether-init is running...");

    unsafe {
        // Mount sysfs
        assert!(
            libc::mount(
                b"sysfs\0".as_ptr() as *const _,
                b"/sys\0".as_ptr() as *const _,
                b"sysfs\0".as_ptr() as *const _,
                0,
                core::ptr::null() as *const _,
            ) == 0
        );
        // Mount procfs
        assert!(
            libc::mount(
                b"proc\0".as_ptr() as *const _,
                b"/proc\0".as_ptr() as *const _,
                b"proc\0".as_ptr() as *const _,
                0,
                core::ptr::null() as *const _,
            ) == 0
        );
        // Mount tmpfs
        assert!(
            libc::mount(
                b"tmpfs\0".as_ptr() as *const _,
                b"/var\0".as_ptr() as *const _,
                b"tmpfs\0".as_ptr() as *const _,
                0,
                core::ptr::null() as *const _,
            ) == 0
        );
        assert!(
            libc::mount(
                b"tmpfs\0".as_ptr() as *const _,
                b"/run\0".as_ptr() as *const _,
                b"tmpfs\0".as_ptr() as *const _,
                0,
                core::ptr::null() as *const _,
            ) == 0
        );
        assert!(
            libc::mount(
                b"tmpfs\0".as_ptr() as *const _,
                b"/tmp\0".as_ptr() as *const _,
                b"tmpfs\0".as_ptr() as *const _,
                0,
                core::ptr::null() as *const _,
            ) == 0
        );
    }

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

    let mut init_process = None;
    let mut init_process_arg = None;

    let kernel_cmdline_file = File::open("/proc/cmdline");
    if let Ok(mut cmdline_file) = kernel_cmdline_file {
        let mut buf = [0u8; 512];
        cmdline_file.read(&mut buf).unwrap();

        let content = String::from_utf8(buf.to_vec()).unwrap();
        println!("Got cmdline {}", content);
        for key_value in content.split(' ') {
            let mut iter = key_value.split('=');
            let key = iter.next().unwrap();
            let value = iter.next().unwrap();
            if key == "init" {
                init_process = Some(value.to_string());
            } else if key == "init_arg" {
                init_process_arg = Some(value.to_string());
            }
        }
    }

    println!("init: Starting desktop process");
    let desktop = unsafe { libc::fork() };
    if desktop == 0 {
        unsafe {
            std::env::set_var("HOME", "/root");
            std::env::set_var("XDG_RUNTIME_DIR", "/run");
            std::env::set_var("SHELL", "/bin/bash");
            std::env::set_var("MESA_SHADER_CACHE_DISABLE", "1");
            std::env::set_var("SDL_VIDEODRIVER", "x11");
            std::env::set_var("SDL_AUDIODRIVER", "dummy");
            // std::env::set_var("WESTON_LIBINPUT_LOG_PRIORITY", "debug");
        }

        let init_process = init_process.unwrap_or("/bin/bash".to_string());

        println!("Got desktop process {}", init_process);

        if init_process_arg.is_some() {
            unsafe {
                libc::execl(
                    init_process.as_ptr() as *const _,
                    init_process.as_ptr() as *const _,
                    init_process_arg.unwrap().as_ptr() as *const _,
                    core::ptr::null::<core::ffi::c_char>(),
                )
            };
        } else {
            unsafe {
                libc::execl(
                    init_process.as_ptr() as *const _,
                    init_process.as_ptr() as *const _,
                    core::ptr::null::<core::ffi::c_char>(),
                )
            };
        }

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
