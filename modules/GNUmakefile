GLOBAL_CFLAGS := -fno-stack-protector -Wno-address-of-packed-member -fPIC -fno-builtin -nostdinc -nostdlib \
                    -I$(CURDIR)/ \
                    -I$(CURDIR)/../kernel/src \
                    -I$(CURDIR)/../kernel/src/libs/fdt \
                    -I$(CURDIR)/../kernel/freestnd-c-hdrs

ifeq ($(BUILD_MODE), debug)
CFLAGS := -g3 -O0 $(GLOBAL_CFLAGS)
else
CFLAGS := -O3 $(GLOBAL_CFLAGS)
endif
export CFLAGS

# Check if the architecture is supported.
ifeq ($(filter $(ARCH),aarch64 loongarch64 riscv64 x86_64),)
    $(error Architecture $(ARCH) not supported)
endif

# Architecture specific internal flags.
ifeq ($(ARCH),x86_64)
    ifeq ($(CC_IS_CLANG),1)
        override CFLAGS += \
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
    override CFLAGS += -march=armv8-a+nofp -mgeneral-regs-only
    override LDFLAGS += \
        -Wl,-m,aarch64elf
endif
ifeq ($(ARCH),riscv64)
    ifeq ($(CC_IS_CLANG),1)
        override CFLAGS += \
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
        override CFLAGS += \
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
	mkdir -p $(PROJECT_ROOT)/modules-$(ARCH)

	$(MAKE) -C drivers
	$(MAKE) -C fs
	$(MAKE) -C net
