CFLAGS := -g3 -O0 -fno-stack-protector -Wno-address-of-packed-member -fvisibility=hidden -fPIC -fno-builtin -nostdinc -nostdlib -I$(shell pwd)/../kernel/src -I$(shell pwd)/../kernel/freestnd-c-hdrs
export CFLAGS

ifeq ($(ARCH),x86_64)
    ifeq ($(CC_IS_CLANG),1)
        override CC += \
            -target x86_64-unknown-none
    endif
    override CFLAGS += \
        -m64 \
        -march=x86-64 \
        -mno-red-zone \
        -mcmodel=large \
        -mno-80387 -mno-mmx -mno-sse -mno-sse2
endif
ifeq ($(ARCH),aarch64)
    ifeq ($(CC_IS_CLANG),1)
        override CC += \
            -target aarch64-unknown-none
    endif
    override CFLAGS +=
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
endif
ifeq ($(ARCH),loongarch64)
    ifeq ($(CC_IS_CLANG),1)
        override CC += \
            -target loongarch64-unknown-none
    endif
    override CFLAGS += \
        -march=loongarch64 \
        -mabi=lp64d \
        -gdwarf-2
endif

all:
	mkdir -p ../modules-$(ARCH)

	$(MAKE) -C ahci
	$(MAKE) -C nvme
	$(MAKE) -C usb
	$(MAKE) -C e1000
	$(MAKE) -C virtio
	$(MAKE) -C vmware_svga
# 	$(MAKE) -C nvidia_open

	$(MAKE) -C msc

	$(MAKE) -C ext

	$(MAKE) -C netserver
