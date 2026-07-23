MAKEFLAGS += -rR --no-print-directory
.SUFFIXES:

ARCH ?= x86_64
BUILD_MODE ?= release
BOOT_PROTOCOL ?= limine
MODULE_VERIFY ?= 0

KERNEL_DIR := $(CURDIR)/na-kernel
KERNEL_MAKE := $(CURDIR)/nix/kernel-make.sh
HOST_COMMAND := $(CURDIR)/nix/host-command.sh
BUILD_DIR := $(CURDIR)/build/$(ARCH)
ROOTFS_IMAGE := $(BUILD_DIR)/rootfs.img
INITRAMFS_IMAGE := $(BUILD_DIR)/initramfs.img
BOOT_IMAGE := $(BUILD_DIR)/boot.img
LIMINE_DIR := $(CURDIR)/build/limine

ifeq ($(ARCH),x86_64)
LIMINE_EFI := BOOTX64.EFI
else ifeq ($(ARCH),aarch64)
LIMINE_EFI := BOOTAA64.EFI
else ifeq ($(ARCH),riscv64)
LIMINE_EFI := BOOTRISCV64.EFI
else ifeq ($(ARCH),loongarch64)
LIMINE_EFI := BOOTLOONGARCH64.EFI
endif

.PHONY: all prepare kernel modules initramfs image run clean distclean
ifeq ($(BOOT_PROTOCOL),limine)
all: image rootfs
else
all: kernel rootfs
endif

prepare:
	$(KERNEL_MAKE) -C $(KERNEL_DIR) prepare ARCH=$(ARCH)

modules:
	$(KERNEL_MAKE) -C $(KERNEL_DIR) modules ARCH=$(ARCH) \
		BUILD_MODE=$(BUILD_MODE) MODULE_VERIFY=$(MODULE_VERIFY)

initramfs: $(INITRAMFS_IMAGE)
$(INITRAMFS_IMAGE): modules nix/flake.nix nix/flake.lock nix/initramfs-init.sh nix/build-artifact.sh
	./nix/build-artifact.sh initramfs $(ARCH) $@

kernel: initramfs
	$(KERNEL_MAKE) -C $(KERNEL_DIR) kernel ARCH=$(ARCH) \
		BUILD_MODE=$(BUILD_MODE) BOOT_PROTOCOL=$(BOOT_PROTOCOL) \
		MODULE_VERIFY=$(MODULE_VERIFY) INITRAMFS_IMAGE=$(INITRAMFS_IMAGE)

rootfs: $(ROOTFS_IMAGE)
$(ROOTFS_IMAGE): nix/flake.nix nix/flake.lock nix/configuration.nix nix/build-artifact.sh
	./nix/build-artifact.sh rootfs $(ARCH) $@

image: $(BOOT_IMAGE)

$(LIMINE_DIR)/limine:
	mkdir -p $(dir $(LIMINE_DIR))
	$(HOST_COMMAND) git clone https://codeberg.org/Limine/Limine \
		--branch=v11.x-binary --depth=1 $(LIMINE_DIR)
	$(HOST_COMMAND) $(MAKE) -C $(LIMINE_DIR)

$(BOOT_IMAGE): kernel $(INITRAMFS_IMAGE) $(LIMINE_DIR)/limine limine.conf
	@if [ "$(BOOT_PROTOCOL)" != limine ]; then \
		echo "boot image creation currently requires BOOT_PROTOCOL=limine" >&2; \
		exit 2; \
	fi
	mkdir -p $(BUILD_DIR)
	$(HOST_COMMAND) dd if=/dev/zero of=$@ bs=1M count=256
	$(HOST_COMMAND) sgdisk --new=1:2M:255M $@
	$(HOST_COMMAND) mkfs.vfat -F 32 --offset 4096 -S 512 $@
	$(HOST_COMMAND) mcopy -i $@@@2M $(KERNEL_DIR)/kernel/bin-$(ARCH)/kernel ::/kernel
	$(HOST_COMMAND) mcopy -i $@@@2M $(INITRAMFS_IMAGE) ::/initramfs.img
	$(HOST_COMMAND) mmd -i $@@@2M ::/EFI ::/EFI/BOOT ::/limine
	$(HOST_COMMAND) mcopy -i $@@@2M $(LIMINE_DIR)/$(LIMINE_EFI) ::/EFI/BOOT/$(LIMINE_EFI)
	$(HOST_COMMAND) mcopy -i $@@@2M limine.conf ::/limine/limine.conf

run: all
	@if [ "$(ARCH)" != x86_64 ]; then \
		echo "the integrated QEMU runner currently supports ARCH=x86_64" >&2; \
		exit 2; \
	fi
	$(HOST_COMMAND) sh -c 'exec qemu-system-x86_64 \
		-M q35 -cpu max -m 8G -smp 4 -display sdl,gl=on -vga none\
		-device virtio-vga-gl -serial stdio \
		-drive if=pflash,unit=0,format=raw,file="$$NA_OVMF_CODE",readonly=on \
		-drive if=none,file="$(BOOT_IMAGE)",format=raw,id=bootdisk \
		-drive if=none,file="$(ROOTFS_IMAGE)",format=raw,id=rootdisk \
		-device ahci,id=ahci \
		-device ide-hd,drive=bootdisk,bus=ahci.0 \
		-device nvme,drive=rootdisk,serial=na-rootfs \
		-netdev user,id=net0 -device e1000,netdev=net0'

clean:
	$(KERNEL_MAKE) -C $(KERNEL_DIR) clean ARCH=$(ARCH)
	rm -rf $(BUILD_DIR)

distclean:
	$(KERNEL_MAKE) -C $(KERNEL_DIR) distclean ARCH=$(ARCH)
	rm -rf build .nix-store
