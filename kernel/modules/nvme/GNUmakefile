override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/nvme/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(CC) -shared $(OBJ) -o ../../modules-$(ARCH)/nvme.ko

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/nvme/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@

# Compilation rules for *.S files.
../../obj-modules-$(ARCH)/nvme/%.S.o: %.S GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@
