# Nuke built-in rules and variables.
MAKEFLAGS += -rR
.SUFFIXES:

export PROJECT_ROOT := $(shell pwd)

export BUILD_MODE ?= debug

export BOOT_PROTOCOL ?= limine

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

.PHONY: all
all: $(IMAGE_NAME).img rootfs-$(ARCH).img

.PHONY: all
all-single: single-$(IMAGE_NAME).img

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
	rm -rf obj-modules-$(ARCH) modules-$(ARCH)

.PHONY: distclean
distclean:
	$(MAKE) -C kernel distclean
	$(MAKE) -C user distclean
	rm -rf *.img assets
	rm -rf obj-modules-$(ARCH) modules-$(ARCH)

clippy:
	$(MAKE) -C kernel clippy

ROOTFS_IMG_SIZE ?= 4096

.PHONY: rootfs-$(ARCH).img
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

$(IMAGE_NAME).img: assets/limine kernel modules
	dd if=/dev/zero of=$(IMAGE_NAME).img bs=1M count=512
	sgdisk --new=1:1M:511M $(IMAGE_NAME).img
	mkfs.vfat -F 32 --offset 2048 -S 512 $(IMAGE_NAME).img
	mcopy -i $(IMAGE_NAME).img@@1M kernel/bin-$(ARCH)/kernel ::/
	mcopy -i $(IMAGE_NAME).img@@1M modules-$(ARCH) ::/modules
ifeq ($(BOOT_PROTOCOL), limine)
	mmd -i $(IMAGE_NAME).img@@1M ::/EFI ::/EFI/BOOT ::/limine
	mcopy -i $(IMAGE_NAME).img@@1M $(EFI_FILE_SINGLE) ::/EFI/BOOT
	mcopy -i $(IMAGE_NAME).img@@1M limine.conf ::/limine
endif

single-$(IMAGE_NAME).img: assets/limine kernel rootfs-$(ARCH).img modules
	dd if=/dev/zero of=single-$(IMAGE_NAME).img bs=1M count=$$(( $(ROOTFS_IMG_SIZE) + 1024 ))
	sgdisk --new=1:1M:511M --new=2:512M:$$(( $$(($(ROOTFS_IMG_SIZE) + 1024 )) * 1024 )) single-$(IMAGE_NAME).img
	mkfs.vfat -F 32 --offset 2048 -S 512 single-$(IMAGE_NAME).img
	mcopy -i single-$(IMAGE_NAME).img@@1M kernel/bin-$(ARCH)/kernel ::/
	mcopy -i single-$(IMAGE_NAME).img@@1M modules-$(ARCH) ::/modules
ifeq ($(BOOT_PROTOCOL), limine)
	mmd -i single-$(IMAGE_NAME).img@@1M ::/EFI ::/EFI/BOOT ::/limine
	mcopy -i single-$(IMAGE_NAME).img@@1M $(EFI_FILE_SINGLE) ::/EFI/BOOT
	mcopy -i single-$(IMAGE_NAME).img@@1M limine.conf ::/limine
endif

	dd if=rootfs-$(ARCH).img of=single-$(IMAGE_NAME).img bs=1M count=$(ROOTFS_IMG_SIZE) seek=512

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
		-device nvme,drive=harddisk,serial=1234 \
		-device nvme,drive=rootdisk,serial=5678 \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
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
		-device usb-storage,drive=harddisk,bus=xhci.0 \
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
		-device nvme,drive=harddisk,serial=1234 \
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
		-drive if=none,file=$(IMAGE_NAME).img,format=raw,id=harddisk \
		-drive if=none,file=rootfs-$(ARCH).img,format=raw,id=rootdisk \
		-device nvme,drive=harddisk,serial=1234 \
		-device nvme,drive=rootdisk,serial=5678 \
		$(QEMUFLAGS)

.PHONY: run-loongarch64
run-loongarch64: assets/ovmf-code-$(ARCH).fd $(IMAGE_NAME).img
	qemu-system-$(ARCH) \
		-M virt \
		-cpu max \
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
	curl -Lo $@ https://github.com/osdev0/edk2-ovmf-nightly/releases/latest/download/ovmf-code-$(ARCH).fd
	case "$(ARCH)" in \
		aarch64) dd if=/dev/zero of=$@ bs=1 count=0 seek=67108864 2>/dev/null;; \
		riscv64) dd if=/dev/zero of=$@ bs=1 count=0 seek=33554432 2>/dev/null;; \
	esac

.PHONY: modules
modules:
	$(MAKE) -C modules -j$(shell nproc)
