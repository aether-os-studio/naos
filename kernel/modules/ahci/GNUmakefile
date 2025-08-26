override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/ahci/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(CC) -shared $(OBJ) -o ../../modules-$(ARCH)/ahci.ko

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/ahci/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@

# Compilation rules for *.S files.
../../obj-modules-$(ARCH)/ahci/%.S.o: %.S GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@
