override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/usb/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(CC) -shared $(OBJ) -o ../../modules-$(ARCH)/usb.ko

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/usb/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@

# Compilation rules for *.S files.
../../obj-modules-$(ARCH)/usb/%.S.o: %.S GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@
