all: $(OBJECTS)
	RUSTFLAGS="-C relocation-model=static" cargo build --target $(ARCH)-unknown-aether
	cp target/x86_64-unknown-aether/debug/test_rust $(SYSROOT)/bin/test_rust

clean:
	cargo clean
