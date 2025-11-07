ifeq ($(ARCH), riscv64)
TARGET ?= riscv64gc-unknown-linux-musl
else
TARGET ?= $(ARCH)-unknown-linux-musl
endif

export RUSTFLAGS := -C target-feature=+crt-static -C link-arg=-static \
					-L$(PROJECT_ROOT)/./user/init/target/$(TARGET) -C linker=$(ARCH)-linux-gnu-ld

TARGET_DIR := $(PROJECT_ROOT)/user/init/target/$(TARGET)
all:
	mkdir -p $(TARGET_DIR)
	ln -sf $(PROJECT_ROOT)/libgcc_$(ARCH).a $(TARGET_DIR)/libgcc.a
	cargo build --target=$(TARGET)
	sudo rm -rf $(shell pwd)/../rootfs-$(ARCH)/sbin/init
	sudo cp -r target/$(TARGET)/debug/init $(shell pwd)/../rootfs-$(ARCH)/sbin/init
