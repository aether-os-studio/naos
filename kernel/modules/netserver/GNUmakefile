override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/netserver/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(CC) $(CFLAGS) -shared $(OBJ) -o ../../modules-$(ARCH)/netserver.ko

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/netserver/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -I$(shell pwd)/ -I$(shell pwd)/lwip/include -I../../src -I../../freestnd-c-hdrs -c $< -o $@
