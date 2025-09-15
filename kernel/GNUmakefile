# Nuke built-in rules and variables.
MAKEFLAGS += -rR
.SUFFIXES:

# This is the name that our final executable will have.
# Change as needed.
override OUTPUT := kernel

ifeq ($(ARCH), x86_64)
ARCH_DIR := src/arch/x64
endif
ifeq ($(ARCH), aarch64)
ARCH_DIR := src/arch/aarch64
endif
ifeq ($(ARCH), riscv64)
ARCH_DIR := src/arch/riscv64
endif
ifeq ($(ARCH), loongarch64)
ARCH_DIR := src/arch/loongarch64
endif

# Install prefix; /usr/local is a good, standard default pick.
PREFIX := /usr/local

# Check if the architecture is supported.
ifeq ($(filter $(ARCH),aarch64 loongarch64 riscv64 x86_64),)
    $(error Architecture $(ARCH) not supported)
endif

# User controllable C flags.
CFLAGS := -g3 -O0 -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-cast-function-type -Wno-sign-compare -Wno-discarded-qualifiers -Wno-address-of-packed-member

# User controllable C preprocessor flags. We set none by default.
CPPFLAGS :=

ifeq ($(ARCH),x86_64)
    # User controllable nasm flags.
    NASMFLAGS := -F dwarf -g
endif

# User controllable linker flags. We set none by default.
LDFLAGS :=

# Ensure the dependencies have been obtained.
ifneq ($(shell ( test '$(MAKECMDGOALS)' = clean || test '$(MAKECMDGOALS)' = distclean ); echo $$?),0)
    ifeq ($(shell ( ! test -d freestnd-c-hdrs || ! test -d src/cc-runtime || ! test -f src/limine.h ); echo $$?),0)
        $(error Please run the ./get-deps script first)
    endif
endif

# Check if CC is Clang.
override CC_IS_CLANG := $(shell ! $(CC) --version 2>/dev/null | grep 'clang' >/dev/null 2>&1; echo $$?)

# Internal C flags that should not be changed by the user.
override CFLAGS += \
    -Wall \
    -Wextra \
    -std=gnu11 \
    -nostdinc \
    -ffreestanding \
    -fno-stack-protector \
    -fno-stack-check \
    -fno-PIC \
    -ffunction-sections \
    -fdata-sections

# Internal C preprocessor flags that should not be changed by the user.
override CPPFLAGS := \
    -I src \
    -I src/fs/ext/lwext4/include \
    -DCONFIG_USE_DEFAULT_CFG \
    -isystem freestnd-c-hdrs \
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
        override CC += \
            -target x86_64-unknown-none
    endif
    override CFLAGS += \
        -m64 \
        -march=x86-64 \
        -mno-red-zone \
        -mcmodel=kernel \
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
        -mabi=lp64 \
        -mno-relax
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
        -gdwarf-2
    override LDFLAGS += \
        -Wl,-m,elf64loongarch \
        -Wl,--no-relax
endif

# Internal linker flags that should not be changed by the user.
override LDFLAGS += \
    -Wl,--build-id=none \
    -nostdlib \
    -static \
    -z max-page-size=0x1000 \
    -Wl,--gc-sections \
    -T linker-$(ARCH).ld

# Use "find" to glob all *.c, *.S, and *.asm files in the tree and obtain the
# object and header dependency file names.
override SRCFILES := $(shell find $(ARCH_DIR) -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES += $(shell find src/drivers -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/fs -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/interrupt -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/libs -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/mm -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/mod -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/init -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/task -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/block -name "*.c" | LC_ALL=C sort)
override SRCFILES += $(shell find src/net -name "*.c" | LC_ALL=C sort)
override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix obj-$(ARCH)/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))
override HEADER_DEPS := $(addprefix obj-$(ARCH)/,$(CFILES:.c=.c.d) $(ASFILES:.S=.S.d))

# Default target. This must come first, before header dependencies.
.PHONY: all
all: bin-$(ARCH)/$(OUTPUT)

# Include header dependencies.
-include $(HEADER_DEPS)

.PHONY: bin-$(ARCH)/$(OUTPUT)
# Link rules for the final executable.
bin-$(ARCH)/$(OUTPUT): GNUmakefile linker-$(ARCH).ld $(OBJ)
	mkdir -p "$$(dirname $@)"
	@$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@.tmp

	gcc kallsyms.c -o kallsyms
	$(NM) -n $@.tmp | ./kallsyms > kallsyms.S
	@$(CC) $(CFLAGS) -c kallsyms.S -o kallsyms.o

	@$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) kallsyms.o -o $@


# Compilation rules for *.c files.
obj-$(ARCH)/src/%.c.o: src/%.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Compilation rules for *.S files.
obj-$(ARCH)/src/%.S.o: src/%.S GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Remove object files and the final executable.
.PHONY: clean
clean:
	rm -rf bin-$(ARCH) obj-$(ARCH)

# Remove everything built and generated including downloaded dependencies.
.PHONY: distclean
distclean:
	rm -rf bin-* obj-* freestnd-c-hdrs src/cc-runtime src/limine.h

# Install the final built executable to its final on-root location.
.PHONY: install
install: all
	install -d "$(DESTDIR)$(PREFIX)/share/$(OUTPUT)"
	install -m 644 bin-$(ARCH)/$(OUTPUT) "$(DESTDIR)$(PREFIX)/share/$(OUTPUT)/$(OUTPUT)-$(ARCH)"

# Try to undo whatever the "install" target did.
.PHONY: uninstall
uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/share/$(OUTPUT)/$(OUTPUT)-$(ARCH)"
	-rmdir "$(DESTDIR)$(PREFIX)/share/$(OUTPUT)"
