ifeq ($(BUILD_MODE), debug)
CFLAGS := -g3 -O0 -fno-stack-protector -Wno-address-of-packed-member -fPIC -fno-builtin -nostdinc -nostdlib -I$(shell pwd)/../kernel/src -I$(shell pwd)/../kernel/src/libs/fdt -I$(shell pwd)/../kernel/freestnd-c-hdrs
else
CFLAGS := -O2 -fno-stack-protector -Wno-address-of-packed-member -fPIC -fno-builtin -nostdinc -nostdlib -I$(shell pwd)/../kernel/src -I$(shell pwd)/../kernel/src/libs/fdt -I$(shell pwd)/../kernel/freestnd-c-hdrs
endif
export CFLAGS

# Architecture specific internal flags.
ifeq ($(ARCH),x86_64)
    ifeq ($(CC_IS_CLANG),1)
        override CC += \
            -target x86_64-unknown-none
    endif
    override CFLAGS += \
        -m64 \
        -march=x86-64 \
        -mno-red-zone \
        -mno-80387 -mno-mmx -mno-sse -mno-sse2
    override LDFLAGS += \
        -Wl,-m,elf_x86_64
    ifeq ($(CC_IS_CLANG),1)
        override LDFLAGS += \
            -lgcc
    endif
    override NASMFLAGS += \
        -f elf64
endif
ifeq ($(ARCH),aarch64)
    ifeq ($(CC_IS_CLANG),1)
        override CC += \
            -target aarch64-unknown-none
    endif
    override CFLAGS +=
    override LDFLAGS += \
        -Wl,-m,aarch64elf
endif
ifeq ($(ARCH),riscv64)
    ifeq ($(CC_IS_CLANG),1)
        override CC += \
            -target riscv64-unknown-none
        override CFLAGS += \
            -march=rv64imac
    else
        override CFLAGS += \
            -march=rv64imac_zicsr_zifencei
    endif
    override CFLAGS += \
        -march=rv64imafd \
        -mabi=lp64d \
        -mno-relax \
        -D__riscv__
    override LDFLAGS += \
        -Wl,-m,elf64lriscv \
        -Wl,--no-relax

endif
ifeq ($(ARCH),loongarch64)
    ifeq ($(CC_IS_CLANG),1)
        override CC += \
            -target loongarch64-unknown-none
    endif
    override CFLAGS += \
        -march=loongarch64 \
        -mabi=lp64d \
        -gdwarf-2 \
		-D__loongarch64__
    override LDFLAGS += \
        -Wl,-m,elf64loongarch \
        -Wl,--no-relax
endif

all:
	mkdir -p ../modules-$(ARCH)

ifeq ($(ARCH), x86_64)
	$(MAKE) -C ahci
	$(MAKE) -C e1000
endif

	$(MAKE) -C nvme

	$(MAKE) -C usb
	$(MAKE) -C virtio
	$(MAKE) -C vmware_svga
# 	$(MAKE) -C nvidia_open

	$(MAKE) -C hub
	$(MAKE) -C hid
	$(MAKE) -C msc

	$(MAKE) -C ext

	$(MAKE) -C netserver
