use std::process::Command;

fn main() {
    println!("Hello, world!");
    let mut p = Command::new("/usr/bin/shell.elf").spawn().unwrap();
    p.wait().unwrap();
    println!("Test shell done!");
}
