override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-drivers-$(ARCH)/virtio/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(CC) -shared $(OBJ) -o ../../drivers-$(ARCH)/virtio.ko

# Compilation rules for *.c files.
../../obj-drivers-$(ARCH)/virtio/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -I../../src -I../../freestnd-c-hdrs -I../../src/libs -I../../src/mm -I../../src/drivers/bus -I../../src/block -c $< -o $@

# Compilation rules for *.S files.
../../obj-drivers-$(ARCH)/virtio/%.S.o: %.S GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -I../../src -I../../freestnd-c-hdrs -I../../src/libs -I../../src/mm -I../../src/drivers/bus -I../../src/block -c $< -o $@
