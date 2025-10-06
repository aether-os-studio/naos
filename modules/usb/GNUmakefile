KM_NAME := usb

override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/$(KM_NAME)/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
ifeq ($(ARCH), riscv64)
	$(CC) $(CFLAGS) -shared $(OBJ) $(PROJECT_ROOT)/libgcc_rv64.a -o ../../modules-$(ARCH)/$(KM_NAME).ko
else
	$(CC) $(CFLAGS) -shared $(OBJ) -o ../../modules-$(ARCH)/$(KM_NAME).ko
endif

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/$(KM_NAME)/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -I$(shell pwd)/ -c $< -o $@
