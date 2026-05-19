# Nuke built-in rules and variables.
MAKEFLAGS += -rR --no-print-directory
.SUFFIXES:

include ../build/common-env.mk

# This is the name that our final executable will have.
# Change as needed.
override OUTPUT := kernel

ARCH_DIR := src/arch/$(ARCH)

# Check if the architecture is supported.
ifeq ($(filter $(ARCH),aarch64 loongarch64 riscv64 x86_64),)
    $(error Architecture $(ARCH) not supported)
endif

GLOBAL_CFLAGS := -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-cast-function-type -Wno-sign-compare -Wno-discarded-qualifiers -Wno-address-of-packed-member
ifeq ($(BOOT_PROTOCOL), limine)
    GLOBAL_CFLAGS += -DCONFIG_BOOT_LIMINE
else ifeq ($(BOOT_PROTOCOL), sbi)
    GLOBAL_CFLAGS += -DCONFIG_BOOT_SBI
else ifeq ($(BOOT_PROTOCOL), laboot)
    GLOBAL_CFLAGS += -DCONFIG_BOOT_LABOOT
else
    $(error Boot protocol $(BOOT_PROTOCOL) not supported)
endif

ifneq ($(MODULE_VERIFY), 0)
	GLOBAL_CFLAGS += -DCONFIG_MODULE_VERIFY
endif

# User controllable C flags.
ifeq ($(BUILD_MODE), debug)
CFLAGS := -g3 -O0 $(GLOBAL_CFLAGS) -DDEBUG
else
CFLAGS := -O3 $(GLOBAL_CFLAGS)
endif

# User controllable C preprocessor flags. We set none by default.
CPPFLAGS :=

ifeq ($(MODULE_VERIFY),0)
else
override CPPFLAGS += -include $(MODULE_SIGN_PUB_HEADER)
endif

ifeq ($(ARCH),x86_64)
    # User controllable nasm flags.
    NASMFLAGS := -F dwarf -g
endif

# User controllable linker flags. We set none by default.
LDFLAGS :=

# Ensure the dependencies have been obtained.
ifneq ($(shell ( test '$(MAKECMDGOALS)' = clean || test '$(MAKECMDGOALS)' = distclean ); echo $$?),0)
    ifeq ($(shell ( ! test -d freestnd-c-hdrs || ! test -f src/limine.h ); echo $$?),0)
        $(error Please run the ./get-deps script first)
    endif
endif

# Internal C flags that should not be changed by the user.
override CFLAGS += \
    -Wall \
    -Wextra \
    -std=gnu11 \
    -nostdinc \
    -ffreestanding \
    -fno-stack-protector \
    -fno-stack-check \
    -fno-PIC

# Internal C preprocessor flags that should not be changed by the user.
override CPPFLAGS := \
    -I src \
    -I src/acpi \
    -I src/libs/fdt \
    -I freestnd-c-hdrs \
    -DCONFIG_USE_DEFAULT_CFG \
    $(CPPFLAGS) \
    -MMD \
    -MP

ifeq ($(ARCH),x86_64)
    # Internal nasm flags that should not be changed by the user.
    override NASMFLAGS += \
        -Wall
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
        -mcmodel=kernel \
        -mno-80387 -mno-mmx -mno-sse -mno-sse2
    override NASMFLAGS += \
        -f elf64
endif
ifeq ($(ARCH),aarch64)
    ifeq ($(CC_IS_CLANG),1)
        override CC += \
            -target aarch64-unknown-none
    endif
    override CFLAGS += -march=armv8-a+nofp -mgeneral-regs-only
    ifeq ($(CC_IS_CLANG),0)
        override LDFLAGS += \
            -Wl,-m,aarch64elf
    endif
endif
ifeq ($(ARCH),riscv64)
    ifeq ($(CC_IS_CLANG),1)
        override CFLAGS += \
            -target riscv64-unknown-none
        override CFLAGS += \
            -march=rv64imac_zicsr_zifencei
    else
        override CFLAGS += \
            -march=rv64imac_zicsr_zifencei
    endif
    override CFLAGS += \
        -march=rv64imafd_zicsr_zifencei \
        -mabi=lp64d \
        -mcmodel=medany \
        -mno-relax \
        -D__riscv__
    ifeq ($(CC_IS_CLANG),0)
        override LDFLAGS += \
            -Wl,-m,elf64lriscv \
            -Wl,--no-relax
    endif

endif
ifeq ($(ARCH),loongarch64)
    ifeq ($(CC_IS_CLANG),1)
        override CFLAGS += \
            -target loongarch64-unknown-none
    endif
    override CFLAGS += \
        -march=loongarch64 \
        -mabi=lp64s \
		-D__loongarch64__
    ifeq ($(CC_IS_CLANG),0)
        override LDFLAGS += \
            -Wl,-m,elf64loongarch \
            -Wl,--no-relax
    endif
endif

# Internal linker flags that should not be changed by the user.
override LDFLAGS += \
    -nostdlib \
    -static \
    -z max-page-size=0x1000 \
    -T linker-$(ARCH)-$(BOOT_PROTOCOL).ld

ifneq ($(CC_IS_CLANG),1)
override LDFLAGS += -Wl,--build-id=none
endif

# Use "find" to glob all *.c, *.S, and *.asm files in the tree and obtain the
# object and header dependency file names.
override SRCFILES := $(shell find $(ARCH_DIR) -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/acpi -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/bpf -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/dev -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/drivers -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/fs -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/irq -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/libs -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/mm -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/mod -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/init -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/task -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/block -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/net -name "*.[Sc]" | LC_ALL=C sort)
ifeq ($(BOOT_PROTOCOL), limine)
override SRCFILES += src/boot/limine_boot.c
endif
ifeq ($(BOOT_PROTOCOL), sbi)
override SRCFILES += src/boot/sbi/boot.S
override SRCFILES += src/boot/sbi_boot.c
endif
ifeq ($(BOOT_PROTOCOL), laboot)
override SRCFILES += src/boot/laboot/boot.S
override SRCFILES += src/boot/la_boot.c
endif
override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix obj-$(ARCH)/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))
override HEADER_DEPS := $(addprefix obj-$(ARCH)/,$(CFILES:.c=.c.d) $(ASFILES:.S=.S.d))

GENERATED_DIR := obj-$(ARCH)/generated
KALLSYMS_C := $(GENERATED_DIR)/kallsyms.c
KALLSYMS_OBJ := $(KALLSYMS_C).o
KALLSYMS_PRELINK := $(GENERATED_DIR)/kernel.prelink
KALLSYMS_AWK := scripts/gen-kallsyms.awk

override OBJ += $(KALLSYMS_OBJ)

ifeq ($(BOOT_PROTOCOL), sbi)
SBI_INITRAMFS_IMAGE := $(PROJECT_ROOT)/initramfs-$(ARCH).img
SBI_INITRAMFS_ASM := $(GENERATED_DIR)/sbi_initramfs.S
SBI_INITRAMFS_OBJ := $(SBI_INITRAMFS_ASM).o

override OBJ += $(SBI_INITRAMFS_OBJ)
endif

ifeq ($(BOOT_PROTOCOL), laboot)
LABOOT_INITRAMFS_IMAGE := $(PROJECT_ROOT)/initramfs-$(ARCH).img
LABOOT_INITRAMFS_ASM := $(GENERATED_DIR)/laboot_initramfs.S
LABOOT_INITRAMFS_OBJ := $(LABOOT_INITRAMFS_ASM).o

override OBJ += $(LABOOT_INITRAMFS_OBJ)
endif

KALLSYMS_PRELINK_OBJ := $(filter-out $(KALLSYMS_OBJ),$(OBJ))

# Default target. This must come first, before header dependencies.
.PHONY: all
all: bin-$(ARCH)/$(OUTPUT)

# Include header dependencies.
-include $(HEADER_DEPS)

ifeq ($(CC_IS_CLANG),1)
LINKER := $(LD)
else
LINKER := $(CC)
endif

.PHONY: bin-$(ARCH)/$(OUTPUT)
# Link rules for the final executable.
bin-$(ARCH)/$(OUTPUT): GNUmakefile linker-$(ARCH)-$(BOOT_PROTOCOL).ld $(OBJ) $(KALLSYMS_C)
	$(call PRINT_STEP,LD,$@)
	$(Q)mkdir -p "$$(dirname $@)"
	$(Q)$(LINKER) $(LDFLAGS) $(OBJ) $(PROJECT_ROOT)/libgcc_$(ARCH).a -o $@

ifeq ($(BOOT_PROTOCOL), sbi)
$(SBI_INITRAMFS_ASM): $(SBI_INITRAMFS_IMAGE) GNUmakefile
	$(call PRINT_STEP,GEN,$@)
	$(Q)mkdir -p "$$(dirname $@)"
	$(Q)printf '%s\n' \
		'.section .initramfs, "a", @progbits' \
		'.balign 16' \
		'.incbin "$(SBI_INITRAMFS_IMAGE)"' \
		'.balign 16' > $@

$(SBI_INITRAMFS_OBJ): $(SBI_INITRAMFS_ASM)
	$(call PRINT_STEP,AS,$<)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -DASM_FILE -c $< -o $@
endif

ifeq ($(BOOT_PROTOCOL), laboot)
$(LABOOT_INITRAMFS_ASM): $(LABOOT_INITRAMFS_IMAGE) GNUmakefile
	$(call PRINT_STEP,GEN,$@)
	$(Q)mkdir -p "$$(dirname $@)"
	$(Q)printf '%s\n' \
		'.section .initramfs, "a", @progbits' \
		'.balign 16' \
		'.incbin "$(LABOOT_INITRAMFS_IMAGE)"' \
		'.balign 16' > $@

$(LABOOT_INITRAMFS_OBJ): $(LABOOT_INITRAMFS_ASM)
	$(call PRINT_STEP,AS,$<)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -DASM_FILE -c $< -o $@
endif


$(KALLSYMS_PRELINK): GNUmakefile linker-$(ARCH)-$(BOOT_PROTOCOL).ld $(KALLSYMS_PRELINK_OBJ)
	$(call PRINT_STEP,LD,$@)
	$(Q)mkdir -p "$$(dirname $@)"
	$(Q)$(LINKER) $(LDFLAGS) $(KALLSYMS_PRELINK_OBJ) $(PROJECT_ROOT)/libgcc_$(ARCH).a -o $@

$(KALLSYMS_C): $(KALLSYMS_PRELINK) $(KALLSYMS_AWK) GNUmakefile
	$(call PRINT_STEP,GEN,$@)
	$(Q)mkdir -p "$$(dirname $@)"
	$(Q)$(NM) -n --defined-only $< | awk -f $(KALLSYMS_AWK) > $@

$(KALLSYMS_OBJ): $(KALLSYMS_C)
	$(call PRINT_STEP,CC,$<)
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Compilation rules for *.c files.
obj-$(ARCH)/src/%.c.o: src/%.c GNUmakefile
	$(call PRINT_STEP,CC,$<)
	$(Q)mkdir -p "$$(dirname $@)"
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Compilation rules for *.S files.
obj-$(ARCH)/src/%.S.o: src/%.S GNUmakefile
	$(call PRINT_STEP,AS,$<)
	$(Q)mkdir -p "$$(dirname $@)"
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -DASM_FILE -c $< -o $@

ifeq ($(MODULE_VERIFY),0)
else
$(MODULE_SIGN_PUB_HEADER): scripts/gen_module_signing_keys.sh scripts/convert_ecc_pubkey.sh
	$(call PRINT_STEP,GEN,$@)
	$(Q)./scripts/gen_module_signing_keys.sh "$(MODULE_SIGN_KEY_DIR)" naos_signing_key_pub
	$(Q)touch "$@"

$(OBJ): $(MODULE_SIGN_PUB_HEADER)
endif

# Remove object files and the final executable.
.PHONY: clean
clean:
	$(call PRINT_STEP,CLEAN,kernel)
	$(Q)rm -rf bin-$(ARCH) obj-$(ARCH)

# Remove everything built and generated including downloaded dependencies.
.PHONY: distclean
distclean:
	$(call PRINT_STEP,DISTCLEAN,kernel)
	$(Q)rm -rf bin-* obj-* freestnd-c-hdrs src/limine.h
