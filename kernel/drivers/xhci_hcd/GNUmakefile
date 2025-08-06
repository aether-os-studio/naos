override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-drivers-$(ARCH)/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))


all: $(OBJ)
	$(LD) -T ../modules_link_script.lds -shared $(OBJ) -o ../../drivers-$(ARCH)/xhci_hcd.ko

# Compilation rules for *.c files.
../../obj-drivers-$(ARCH)/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@

# Compilation rules for *.S files.
../../obj-drivers-$(ARCH)/%.S.o: %.S GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@
