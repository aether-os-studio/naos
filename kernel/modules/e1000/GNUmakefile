KM_NAME := e1000

override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/$(KM_NAME)/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(CC) $(CFLAGS) -shared $(OBJ) -o ../../modules-$(ARCH)/$(KM_NAME).ko

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/$(KM_NAME)/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -I$(shell pwd)/ -I../../src -I../../freestnd-c-hdrs -c $< -o $@
