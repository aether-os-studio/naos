# Nuke built-in rules and variables.
MAKEFLAGS += -rR
.SUFFIXES:

# Target architecture to build for. Default to x86_64.
export ARCH ?= x86_64

export PKGS ?= 

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
export CC := $(ARCH)-unknown-linux-gnu-gcc
export CXX := $(ARCH)-unknown-linux-gnu-g++
export LD := $(ARCH)-unknown-linux-gnu-ld
export AR := $(ARCH)-unknown-linux-gnu-ar
export NM := $(ARCH)-unknown-linux-gnu-nm
export RANLIB := $(ARCH)-unknown-linux-gnu-ranlib
endif

export ROOT_DIR := "$(shell pwd)"

KVM ?= 0
HVF ?= 0
SMP ?= 2
MEM ?= 8G
SER ?= 0
MON ?= 0

# Default user QEMU flags. These are appended to the QEMU command calls.
QEMUFLAGS := -m $(MEM) -smp $(SMP) -cpu max

DEBUG ?= 0

ifeq ($(DEBUG), 1)
override QEMUFLAGS := $(QEMUFLAGS) -s -S
endif

ifeq ($(KVM), 1)
override QEMUFLAGS := $(QEMUFLAGS) --enable-kvm
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

override IMAGE_NAME := naos-$(ARCH)

# Toolchain for building the 'limine' executable for the host.
HOST_CC := cc
HOST_CFLAGS := -g -O2 -pipe
HOST_CPPFLAGS :=
HOST_LDFLAGS :=
HOST_LIBS :=

.PHONY: all
all: $(IMAGE_NAME).img rootfs-$(ARCH).img

.PHONY: kernel
kernel:
	./kernel/get-deps
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

.PHONY: distclean
distclean:
	$(MAKE) -C kernel distclean
	$(MAKE) -C user distclean
	rm -rf *.img assets

clippy:
	$(MAKE) -C kernel clippy

ROOTFS_IMG_SIZE ?= 2048

.PHONY: rootfs-$(ARCH).img
rootfs-$(ARCH).img: user/.build-stamp-$(ARCH)
	dd if=/dev/zero bs=1M count=0 seek=$(ROOTFS_IMG_SIZE) of=rootfs-$(ARCH).img
	mkfs.ext2 -F -q -d user/rootfs-$(ARCH) rootfs-$(ARCH).img

ifeq ($(ARCH),x86_64)
EFI_FILE = assets/limine/BOOTX64.EFI:EFI/BOOT/BOOTX64.EFI
else ifeq ($(ARCH),aarch64)
EFI_FILE = assets/limine/BOOTAA64.EFI:EFI/BOOT/BOOTAA64.EFI
else ifeq ($(ARCH),riscv64)
EFI_FILE = assets/limine/BOOTRISCV64.EFI:EFI/BOOT/BOOTRISCV64.EFI
else ifeq ($(ARCH),loongarch64)
EFI_FILE = assets/limine/BOOTLOONGARCH64.EFI:EFI/BOOT/BOOTLOONGARCH64.EFI
endif
$(IMAGE_NAME).img: assets/limine assets/oib kernel
	assets/oib -o $(IMAGE_NAME).img -f $(EFI_FILE) \
		-d kernel/drivers-$(ARCH):drivers \
		-f kernel/bin-$(ARCH)/kernel:boot/kernel \
		-f limine.conf:boot/limine/limine.conf \
		-f assets/limine/limine-bios.sys:boot/limine/limine-bios.sys

.PHONY: run
run: run-$(ARCH)

.PHONY: run-x86_64
run-x86_64: assets/ovmf-code-$(ARCH).fd all
	qemu-system-$(ARCH) \
		-M q35 \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=$(IMAGE_NAME).img,format=raw,id=harddisk \
		-drive if=none,file=rootfs-$(ARCH).img,format=raw,id=rootdisk \
		-device qemu-xhci,id=xhci \
		-device nvme,drive=harddisk,serial=1234 \
		-device nvme,drive=rootdisk,serial=5678 \
		-vga vmware \
		$(QEMUFLAGS)

.PHONY: run-aarch64
run-aarch64: assets/ovmf-code-$(ARCH).fd all
	qemu-system-$(ARCH) \
		-M virt,gic-version=3 \
		-cpu cortex-a76 \
		-device ramfb \
		-device qemu-xhci,id=xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=$(IMAGE_NAME).img,format=raw,id=harddisk \
		-drive if=none,file=rootfs-$(ARCH).img,format=raw,id=rootdisk \
		-device nvme,drive=harddisk,serial=1234 \
		-device nvme,drive=rootdisk,serial=5678 \
		$(QEMUFLAGS)

.PHONY: run-riscv64
run-riscv64: assets/ovmf-code-$(ARCH).fd all
	qemu-system-$(ARCH) \
		-M virt \
		-cpu rv64 \
		-device ramfb \
		-device qemu-xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=assets/ovmf-code-$(ARCH).fd,readonly=on \
		-hda $(IMAGE_NAME).img \
		$(QEMUFLAGS)

.PHONY: run-loongarch64
run-loongarch64: assets/ovmf-code-$(ARCH).fd all
	qemu-system-$(ARCH) \
		-M virt \
		-cpu la464 \
		-device ramfb \
		-device qemu-xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=ovmf/ovmf-code-$(ARCH).fd,readonly=on \
		-hda $(IMAGE_NAME).img \
		$(QEMUFLAGS)

OIB_VERSION = v0.3.0
OIB_ARCH = $(shell uname -m)-unknown-linux-gnu
OIB_URL = https://github.com/wenxuanjun/oib/releases/download/$(OIB_VERSION)/oib-$(OIB_ARCH).tar.gz

assets/oib:
	mkdir -p assets
	curl -L $(OIB_URL) | tar -xz -C /tmp
	mv /tmp/oib-$(OIB_ARCH)/oib assets/oib
	rm -rf /tmp/oib-$(OIB_ARCH)
	chmod +x assets/oib

assets/limine:
	rm -rf assets/limine
	git clone https://github.com/limine-bootloader/limine.git --branch=v9.x-binary --depth=1 assets/limine
	$(MAKE) -C assets/limine \
		CC="$(HOST_CC)" \
		CFLAGS="$(HOST_CFLAGS)" \
		CPPFLAGS="$(HOST_CPPFLAGS)" \
		LDFLAGS="$(HOST_LDFLAGS)" \
		LIBS="$(HOST_LIBS)"

assets/ovmf-code-$(ARCH).fd:
	mkdir -p assets
	curl -Lo $@ https://github.com/osdev0/edk2-ovmf-nightly/releases/latest/download/ovmf-code-$(ARCH).fd
	case "$(ARCH)" in \
		aarch64) dd if=/dev/zero of=$@ bs=1 count=0 seek=67108864 2>/dev/null;; \
		riscv64) dd if=/dev/zero of=$@ bs=1 count=0 seek=33554432 2>/dev/null;; \
	esac
