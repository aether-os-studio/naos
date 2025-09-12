export PKG_CONFIG_SYSROOT_DIR=$(shell pwd)/assets
export PKG_CONFIG_PATH="$(PKG_CONFIG_SYSROOT_DIR)/usr/lib/pkgconfig"
export RUSTFLAGS=-C link-arg=-fno-lto

all:
	cargo build --target=$(ARCH)-unknown-linux-musl
	sudo rm -rf $(shell pwd)/../rootfs-$(ARCH)/sbin/init
	sudo cp -r target/$(ARCH)-unknown-linux-musl/debug/init $(shell pwd)/../rootfs-$(ARCH)/sbin/init
