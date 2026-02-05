# Nuke built-in rules and variables.
MAKEFLAGS += -rR
.SUFFIXES:

export PROJECT_ROOT := $(shell pwd)

export BUILD_MODE ?= debug

export BOOT_PROTOCOL ?= limine

# mixed or monolithic
export KERNEL_MODULE ?= mixed

# Target architecture to build for. Default to x86_64.
export ARCH ?= x86_64

ifeq ($(ARCH), x86_64)
ARCH_DIR := x64
else
ARCH_DIR := $(ARCH)
endif

# User controllable C compiler command.
ifeq ($(ARCH), x86_64)
export CC := $(ARCH)-linux-gnu-gcc
export CXX := $(ARCH)-linux-gnu-g++
export LD := $(ARCH)-linux-gnu-ld
export AR := $(ARCH)-linux-gnu-ar
export NM := $(ARCH)-linux-gnu-nm
export RANLIB := $(ARCH)-linux-gnu-ranlib
endif
ifeq ($(ARCH), aarch64)
export CC := $(ARCH)-linux-gnu-gcc
export CXX := $(ARCH)-linux-gnu-g++
export LD := $(ARCH)-linux-gnu-ld
export AR := $(ARCH)-linux-gnu-ar
export NM := $(ARCH)-linux-gnu-nm
export RANLIB := $(ARCH)-linux-gnu-ranlib
endif
ifeq ($(ARCH), riscv64)
export CC := $(ARCH)-linux-gnu-gcc
export CXX := $(ARCH)-linux-gnu-g++
export LD := $(ARCH)-linux-gnu-ld
export AR := $(ARCH)-linux-gnu-ar
export NM := $(ARCH)-linux-gnu-nm
export RANLIB := $(ARCH)-linux-gnu-ranlib
endif
ifeq ($(ARCH), loongarch64)
export CC := $(ARCH)-linux-gnu-gcc
export CXX := $(ARCH)-linux-gnu-g++
export LD := $(ARCH)-linux-gnu-ld
export AR := $(ARCH)-linux-gnu-ar
export NM := $(ARCH)-linux-gnu-nm
export RANLIB := $(ARCH)-linux-gnu-ranlib
endif

export ROOT_DIR := "$(shell pwd)"

KVM ?= 0
HVF ?= 0
SMP ?= 2
MEM ?= 8G
SER ?= 0
MON ?= 0

# Default user QEMU flags. These are appended to the QEMU command calls.
QEMUFLAGS := -m $(MEM) -smp $(SMP)

export EXTRA ?= 

DEBUG ?= 0

ifeq ($(DEBUG), 1)
override QEMUFLAGS := $(QEMUFLAGS) -s -S
endif

ifeq ($(KVM), 1)
override QEMUFLAGS := $(QEMUFLAGS) -cpu host,migratable=off --enable-kvm
else
override QEMUFLAGS := $(QEMUFLAGS) -cpu max
endif

ifeq ($(SER), 1)
override QEMUFLAGS := $(QEMUFLAGS) -serial stdio
endif

ifeq ($(MON), 1)
override QEMUFLAGS := $(QEMUFLAGS) -monitor stdio
endif

ifeq ($(HVF), 1)
override QEMUFLAGS := $(QEMUFLAGS) --accel hvf
endif

override QEMUFLAGS := $(QEMUFLAGS) $(EXTRA)

override IMAGE_NAME := naos-$(ARCH)

# Toolchain for building the 'limine' executable for the host.
HOST_CC := cc
HOST_CFLAGS := -g -O2 -pipe
HOST_CPPFLAGS :=
HOST_LDFLAGS :=
HOST_LIBS :=

LIBGCC_VERSION ?= 2025-08-21

prepare: libgcc_$(ARCH).a liballoc-$(ARCH).a
	./kernel/get-deps

.PHONY: liballoc-$(ARCH).a
liballoc-$(ARCH).a:
	wget https://github.com/plos-clan/liballoc/releases/download/release/liballoc-$(ARCH).a -O liballoc-$(ARCH).a

.PHONY: libgcc_$(ARCH).a
libgcc_$(ARCH).a:
	wget https://github.com/osdev0/libgcc-binaries/releases/download/$(LIBGCC_VERSION)/libgcc-$(ARCH).a -O libgcc_$(ARCH).a

.PHONY: all
all: $(IMAGE_NAME).img rootfs-$(ARCH).img

.PHONY: all
all-single: single-$(IMAGE_NAME).img

.PHONY: kernel
kernel:
	$(MAKE) -C kernel -j$(shell nproc)

user: user/.build-stamp-$(ARCH)
user/.build-stamp-$(ARCH):
	$(MAKE) -C user
	touch $@

.PHONY: clean
clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C user clean
	rm -rf $(IMAGE_NAME).img
	rm -rf rootfs-$(ARCH) obj-modules-$(ARCH) modules-$(ARCH)

.PHONY: distclean
distclean:
	$(MAKE) -C kernel distclean
	$(MAKE) -C user distclean
	rm -rf *.img assets
	rm -rf rootfs-$(ARCH) obj-modules-$(ARCH) modules-$(ARCH)

clippy:
	$(MAKE) -C kernel clippy

ROOTFS_IMG_SIZE ?= 4096

rootfs-$(ARCH).img: user/.build-stamp-$(ARCH)
	dd if=/dev/zero bs=1M count=0 seek=$(ROOTFS_IMG_SIZE) of=rootfs-$(ARCH).img
	sudo mkfs.ext2 -F -q -d user/rootfs-$(ARCH) rootfs-$(ARCH).img

ifeq ($(ARCH),x86_64)
EFI_FILE_SINGLE = assets/limine/BOOTX64.EFI
else ifeq ($(ARCH),aarch64)
EFI_FILE_SINGLE = assets/limine/BOOTAA64.EFI
else ifeq ($(ARCH),riscv64)
EFI_FILE_SINGLE = assets/limine/BOOTRISCV64.EFI
else ifeq ($(ARCH),loongarch64)
EFI_FILE_SINGLE = assets/limine/BOOTLOONGARCH64.EFI
endif

$(IMAGE_NAME).img: assets/limine modules kernel initramfs-$(ARCH).img rootfs-$(ARCH).img
	dd if=/dev/zero of=$(IMAGE_NAME).img bs=1M count=512
	sgdisk --new=1:1M:511M $(IMAGE_NAME).img
	mkfs.vfat -F 32 --offset 2048 -S 512 $(IMAGE_NAME).img
	mcopy -i $(IMAGE_NAME).img@@1M kernel/bin-$(ARCH)/kernel ::/
ifeq ($(KERNEL_MODULE), mixed)
	mcopy -i $(IMAGE_NAME).img@@1M initramfs-$(ARCH).img ::/initramfs.img
endif
ifeq ($(BOOT_PROTOCOL), limine)
	mmd -i $(IMAGE_NAME).img@@1M ::/EFI ::/EFI/BOOT ::/limine
	mcopy -i $(IMAGE_NAME).img@@1M $(EFI_FILE_SINGLE) ::/EFI/BOOT
ifeq ($(ARCH), x86_64)
	mcopy -i $(IMAGE_NAME).img@@1M limine_x86_64_$(KERNEL_MODULE).conf ::/limine/limine.conf
else
	mcopy -i $(IMAGE_NAME).img@@1M limine_$(KERNEL_MODULE).conf ::/limine/limine.conf
endif
endif
ifeq ($(BOOT_PROTOCOL), multiboot2)
	mmd -i $(IMAGE_NAME).img@@1M ::/EFI ::/EFI/BOOT ::/limine
	mcopy -i $(IMAGE_NAME).img@@1M $(EFI_FILE_SINGLE) ::/EFI/BOOT
	mcopy -i $(IMAGE_NAME).img@@1M limine_multiboot2_$(KERNEL_MODULE).conf ::/limine/limine.conf
endif

TOTAL_IMG_SIZE=$$(( $(ROOTFS_IMG_SIZE) + 32 ))

single-$(IMAGE_NAME).img: assets/limine modules kernel initramfs-$(ARCH).img rootfs-$(ARCH).img
	dd if=/dev/zero of=single-$(IMAGE_NAME).img bs=1M count=$(TOTAL_IMG_SIZE)
	sgdisk --new=1:1M:31M --new=2:32M:0 single-$(IMAGE_NAME).img
	mkfs.vfat -F 32 --offset 2048 -S 512 single-$(IMAGE_NAME).img
	mcopy -i single-$(IMAGE_NAME).img@@1M kernel/bin-$(ARCH)/kernel ::/
ifeq ($(KERNEL_MODULE), mixed)
	mcopy -i single-$(IMAGE_NAME).img@@1M initramfs-$(ARCH).img ::/initramfs.img
endif
ifeq ($(BOOT_PROTOCOL), limine)
	mmd -i single-$(IMAGE_NAME).img@@1M ::/EFI ::/EFI/BOOT ::/limine
	mcopy -i single-$(IMAGE_NAME).img@@1M $(EFI_FILE_SINGLE) ::/EFI/BOOT
ifeq ($(ARCH), x86_64)
	mcopy -i single-$(IMAGE_NAME).img@@1M limine_x86_64_$(KERNEL_MODULE).conf ::/limine/limine.conf
else
	mcopy -i single-$(IMAGE_NAME).img@@1M limine_$(KERNEL_MODULE).conf ::/limine/limine.conf
endif
endif

	dd if=rootfs-$(ARCH).img of=single-$(IMAGE_NAME).img bs=1M count=$(ROOTFS_IMG_SIZE) seek=32

.PHONY: run
run: run-$(ARCH)

.PHONY: run-single
run-single: run-$(ARCH)-single

.PHONY: run-x86_64
run-x86_64: assets/ovmf-code-$(ARCH).fd all
	qemu-system-$(ARCH) \
		-M q35 \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=$(IMAGE_NAME).img,format=raw,id=harddisk \
		-drive if=none,file=rootfs-$(ARCH).img,format=raw,id=rootdisk \
		-device qemu-xhci,id=xhci \
		-device ahci,id=ahci \
		-device ide-hd,drive=harddisk,bus=ahci.0 \
		-device nvme,drive=rootdisk,serial=5678 \
		-netdev user,id=net0 \
		-device e1000,netdev=net0 \
		-rtc base=utc \
		-vga vmware \
		$(QEMUFLAGS)

.PHONY: run-x86_64-single
run-x86_64-single: assets/ovmf-code-$(ARCH).fd all-single
	qemu-system-$(ARCH) \
		-M q35 \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=single-$(IMAGE_NAME).img,format=raw,id=harddisk \
		-device qemu-xhci,id=xhci \
		-device usb-kbd \
		-device usb-mouse \
		-device usb-storage,drive=harddisk,bus=xhci.0 \
		-vga vmware \
		$(QEMUFLAGS)

.PHONY: run-aarch64
run-aarch64: assets/ovmf-code-$(ARCH).fd all
	qemu-system-$(ARCH) \
		-M virt \
		-cpu cortex-a72 \
		-device ramfb \
		-device qemu-xhci,id=xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=$(IMAGE_NAME).img,format=raw,id=harddisk \
		-drive if=none,file=rootfs-$(ARCH).img,format=raw,id=rootdisk \
		-device virtio-blk-pci,drive=harddisk \
		-device usb-storage,drive=rootdisk \
		$(QEMUFLAGS)

.PHONY: run-aarch64-single
run-aarch64-single: assets/ovmf-code-$(ARCH).fd all-single
	qemu-system-$(ARCH) \
		-M virt,gic-version=3 \
		-cpu cortex-a76 \
		-device ramfb \
		-device qemu-xhci,id=xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=single-$(IMAGE_NAME).img,format=raw,id=harddisk \
		-device usb-storage,drive=harddisk \
		$(QEMUFLAGS)

.PHONY: run-riscv64
run-riscv64: assets/ovmf-code-$(ARCH).fd all
ifeq ($(BOOT_PROTOCOL), opensbi)
	qemu-system-$(ARCH) \
		-M virt \
		-cpu rv64 \
		-device ramfb \
		-device qemu-xhci \
		-device usb-kbd \
		-device usb-mouse \
		-kernel kernel/bin-$(ARCH)/kernel \
		-drive if=none,file=rootfs-$(ARCH).img,format=raw,id=rootdisk \
		-device virtio-blk-device,drive=rootdisk,bus=virtio-mmio-bus.0 \
		-netdev user,id=net0 \
		-device virtio-net-device,netdev=net0,bus=virtio-mmio-bus.1 \
		$(QEMUFLAGS)
else
	qemu-system-$(ARCH) \
		-M virt \
		-cpu rv64 \
		-device ramfb \
		-device qemu-xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=$(IMAGE_NAME).img,format=raw,id=harddisk \
		-drive if=none,file=rootfs-$(ARCH).img,format=raw,id=rootdisk \
		-device nvme,drive=harddisk,serial=1234 \
		-device nvme,drive=rootdisk,serial=5678 \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
		$(QEMUFLAGS)
endif

.PHONY: run-riscv64
run-riscv64-single: assets/ovmf-code-$(ARCH).fd all-single
	qemu-system-$(ARCH) \
		-M virt \
		-cpu rv64 \
		-device ramfb \
		-device qemu-xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=single-$(IMAGE_NAME).img,format=raw,id=harddisk \
		-device usb-storage,drive=harddisk \
		$(QEMUFLAGS)

.PHONY: run-loongarch64
run-loongarch64: assets/ovmf-code-$(ARCH).fd $(IMAGE_NAME).img
	qemu-system-$(ARCH) \
		-M virt \
		-device ramfb \
		-device qemu-xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-hda $(IMAGE_NAME).img \
		$(QEMUFLAGS)

assets/limine:
	rm -rf assets/limine
	git clone https://codeberg.org/Limine/Limine --branch=v10.x-binary --depth=1 assets/limine
	$(MAKE) -C assets/limine \
		CC="$(HOST_CC)" \
		CFLAGS="$(HOST_CFLAGS)" \
		CPPFLAGS="$(HOST_CPPFLAGS)" \
		LDFLAGS="$(HOST_LDFLAGS)" \
		LIBS="$(HOST_LIBS)"

assets/ovmf-code-$(ARCH).fd:
	mkdir -p assets
	curl -Lo assets/edk2-ovmf.tar.gz https://github.com/osdev0/edk2-ovmf-nightly/releases/download/nightly-20251204T012528Z/edk2-ovmf.tar.gz
	tar -zxvf assets/edk2-ovmf.tar.gz -C assets/

	cp -r assets/edk2-ovmf/ovmf-code-$(ARCH).fd $@

	case "$(ARCH)" in \
		aarch64) dd if=/dev/zero of=$@ bs=1 count=0 seek=67108864 2>/dev/null;; \
		riscv64) dd if=/dev/zero of=$@ bs=1 count=0 seek=33554432 2>/dev/null;; \
	esac

.PHONY: modules
modules:
	$(MAKE) -C modules -j$(shell nproc)

.PHONY: initramfs-$(ARCH).img
initramfs-$(ARCH).img: rootfs-$(ARCH).img
	sh mkinitcpio.sh
