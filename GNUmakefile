# Nuke built-in rules and variables.
MAKEFLAGS += -rR
.SUFFIXES:

# Target architecture to build for. Default to x86_64.
export ARCH := x86_64

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

export ROOT_DIR := $(shell pwd)

KVM ?= 0
HVF ?= 0
SMP ?= 2
MEM ?= 4G
SER ?= 0
MON ?= 0

# Default user QEMU flags. These are appended to the QEMU command calls.
QEMUFLAGS := -m $(MEM) -smp $(SMP)

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
all: $(IMAGE_NAME).hdd

.PHONY: run
run: run-hdd-$(ARCH)

.PHONY: run-hdd-x86_64
run-hdd-x86_64: ovmf/ovmf-code-$(ARCH).fd $(IMAGE_NAME).hdd
	qemu-system-$(ARCH) \
		-M q35 \
		-drive if=pflash,unit=0,format=raw,file=ovmf/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=$(IMAGE_NAME).hdd,format=raw,id=harddisk \
		-drive if=none,file=rootfs-$(ARCH).hdd,format=raw,id=rootdisk \
		-device ahci,id=ahci \
		-device qemu-xhci,id=xhci \
		-device nvme,drive=harddisk,serial=1234 \
		-device usb-storage,bus=xhci.0,drive=rootdisk \
		$(QEMUFLAGS)

.PHONY: run-hdd-aarch64
run-hdd-aarch64: ovmf/ovmf-code-$(ARCH).fd $(IMAGE_NAME).hdd
	qemu-system-$(ARCH) \
		-M virt,gic-version=3 \
		-cpu cortex-a76 \
		-device ramfb \
		-device qemu-xhci,id=xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=ovmf/ovmf-code-$(ARCH).fd,readonly=on \
		-drive if=none,file=$(IMAGE_NAME).hdd,format=raw,id=harddisk \
		-drive if=none,file=rootfs-$(ARCH).hdd,format=raw,id=rootdisk \
		-device nvme,drive=harddisk,serial=1234 \
		-device nvme,drive=rootdisk,serial=5678 \
		$(QEMUFLAGS)

.PHONY: run-hdd-riscv64
run-hdd-riscv64: ovmf/ovmf-code-$(ARCH).fd $(IMAGE_NAME).hdd
	qemu-system-$(ARCH) \
		-M virt \
		-cpu rv64 \
		-device ramfb \
		-device qemu-xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=ovmf/ovmf-code-$(ARCH).fd,readonly=on \
		-hda $(IMAGE_NAME).hdd \
		$(QEMUFLAGS)

.PHONY: run-hdd-loongarch64
run-hdd-loongarch64: ovmf/ovmf-code-$(ARCH).fd $(IMAGE_NAME).hdd
	qemu-system-$(ARCH) \
		-M virt \
		-cpu la464 \
		-device ramfb \
		-device qemu-xhci \
		-device usb-kbd \
		-device usb-mouse \
		-drive if=pflash,unit=0,format=raw,file=ovmf/ovmf-code-$(ARCH).fd,readonly=on \
		-hda $(IMAGE_NAME).hdd \
		$(QEMUFLAGS)

ovmf/ovmf-code-$(ARCH).fd:
	mkdir -p ovmf
	curl -Lo $@ https://github.com/osdev0/edk2-ovmf-nightly/releases/latest/download/ovmf-code-$(ARCH).fd
	case "$(ARCH)" in \
		aarch64) dd if=/dev/zero of=$@ bs=1 count=0 seek=67108864 2>/dev/null;; \
		riscv64) dd if=/dev/zero of=$@ bs=1 count=0 seek=33554432 2>/dev/null;; \
	esac

limine/limine:
	rm -rf limine
	git clone https://github.com/limine-bootloader/limine.git --branch=v9.x-binary --depth=1
	$(MAKE) -C limine \
		CC="$(HOST_CC)" \
		CFLAGS="$(HOST_CFLAGS)" \
		CPPFLAGS="$(HOST_CPPFLAGS)" \
		LDFLAGS="$(HOST_LDFLAGS)" \
		LIBS="$(HOST_LIBS)"

kernel-deps:
	./kernel/get-deps
	touch kernel-deps

.PHONY: kernel
kernel: kernel-deps
	$(MAKE) -C kernel
	$(MAKE) -C user

.PHONY: user
user:
	$(MAKE) -C user all

$(IMAGE_NAME).hdd: limine/limine kernel
	rm -rf $(IMAGE_NAME).hdd
	dd if=/dev/zero bs=1M count=0 seek=128 of=$(IMAGE_NAME).hdd
ifeq ($(ARCH),x86_64)
	PATH=$$PATH:/usr/sbin:/sbin sgdisk $(IMAGE_NAME).hdd -n 1:2048 -t 1:ef00 -m 1
else
	PATH=$$PATH:/usr/sbin:/sbin sgdisk $(IMAGE_NAME).hdd -n 1:2048 -t 1:ef00
endif
	mformat -i $(IMAGE_NAME).hdd@@1M
	mmd -i $(IMAGE_NAME).hdd@@1M ::/EFI ::/EFI/BOOT ::/boot ::/boot/limine
	mcopy -i $(IMAGE_NAME).hdd@@1M kernel/bin-$(ARCH)/kernel ::/boot
	mcopy -i $(IMAGE_NAME).hdd@@1M limine.conf ::/boot/limine
ifeq ($(ARCH),x86_64)
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/limine-bios.sys ::/boot/limine
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/BOOTX64.EFI ::/EFI/BOOT
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/BOOTIA32.EFI ::/EFI/BOOT
endif
ifeq ($(ARCH),aarch64)
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/BOOTAA64.EFI ::/EFI/BOOT
endif
ifeq ($(ARCH),riscv64)
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/BOOTRISCV64.EFI ::/EFI/BOOT
endif
ifeq ($(ARCH),loongarch64)
	mcopy -i $(IMAGE_NAME).hdd@@1M limine/BOOTLOONGARCH64.EFI ::/EFI/BOOT
endif

	dd if=/dev/zero bs=1M count=2048 of=rootfs-$(ARCH).hdd
	mkfs.ext2 rootfs-$(ARCH).hdd
	mkdir -p mnt
	sudo mount rootfs-$(ARCH).hdd mnt
	sudo cp -r user/rootfs-$(ARCH)/* mnt/
	sudo umount mnt
	rm -rf mnt

.PHONY: clean
clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C user clean
	rm -rf $(IMAGE_NAME).hdd rootfs-$(ARCH).hdd

.PHONY: distclean
distclean:
	$(MAKE) -C kernel distclean
	$(MAKE) -C user distclean
	rm -rf *.hdd kernel-deps limine ovmf
