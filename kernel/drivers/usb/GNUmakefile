override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-drivers-$(ARCH)/usb/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(CC) -shared $(OBJ) -o ../../drivers-$(ARCH)/usb.ko

# Compilation rules for *.c files.
../../obj-drivers-$(ARCH)/usb/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@

# Compilation rules for *.S files.
../../obj-drivers-$(ARCH)/usb/%.S.o: %.S GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@
