override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFLAGS += -I. -I./lwext4/include

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/ext/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(CC) -shared $(OBJ) -o ../../modules-$(ARCH)/ext.ko

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/ext/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@

# Compilation rules for *.S files.
../../obj-modules-$(ARCH)/ext/%.S.o: %.S GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -c $< -o $@
