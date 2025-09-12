all:
	cargo build --target=$(ARCH)-unknown-linux-musl
	sudo rm -rf $(shell pwd)/../rootfs-$(ARCH)/sbin/init
	sudo cp -r target/$(ARCH)-unknown-linux-musl/debug/init $(shell pwd)/../rootfs-$(ARCH)/sbin/init
