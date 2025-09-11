all:
	cargo build --target=$(ARCH)-unknown-linux-musl
	sudo cp target/$(ARCH)-unknown-linux-musl/debug/init $(shell pwd)/../rootfs-$(ARCH)/sbin/init
