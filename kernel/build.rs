#![allow(deprecated)]

use std::{path::PathBuf, str::FromStr};

use bindgen::CargoCallbacks;

fn main() {
    let wrapper_h =
        PathBuf::from_str("src/rust/wrapper.h").expect("Failed to parse 'wrapper.h' path");

    let out_path = PathBuf::from(String::from("src/rust/bindings"));

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.

    let builder = bindgen::Builder::default()
        .clang_arg("-Isrc")
        .clang_arg("-Ifreestnd-c-hdrs")
        // The input header we would like to generate
        // bindings for.
        .header(wrapper_h.to_str().unwrap())
        .blocklist_file("src/include/bindings/bindings.h")
        .clang_arg("-v")
        .clang_arg("-nostdinc")
        // 使用core，并将c语言的类型改为core::ffi，而不是使用std库。
        .use_core()
        .ctypes_prefix("::core::ffi")
        .generate_inline_functions(true)
        .raw_line("#![allow(dead_code)]")
        .raw_line("#![allow(non_snake_case)]")
        .raw_line("#![allow(non_upper_case_globals)]")
        .raw_line("#![allow(non_camel_case_types)]")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(CargoCallbacks::new()));

    let bindings = builder.generate().expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join(format!("bindings_{}.rs", env!("ARCH"))))
        .expect("Couldn't write bindings!");
}
