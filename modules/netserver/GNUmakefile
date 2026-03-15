KM_NAME := netserver

override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)
override SRCFILES := \
	$(shell find . -maxdepth 1 -name "*.[Sc]" | LC_ALL=C sort) \
	$(shell find ./lwip/api -maxdepth 1 \( -name "api_lib.c" -o -name "api_msg.c" -o -name "err.c" -o -name "if_api.c" -o -name "netbuf.c" -o -name "netifapi.c" -o -name "tcpip.c" \) | LC_ALL=C sort) \
	$(shell find ./lwip/core -maxdepth 1 -name "*.c" | LC_ALL=C sort) \
	$(shell find ./lwip/core/ipv4 -maxdepth 1 -name "*.c" | LC_ALL=C sort) \
	$(shell find ./lwip/core/ipv6 -maxdepth 1 -name "*.c" | LC_ALL=C sort) \
	$(shell find ./lwip/netif -maxdepth 1 -name "ethernet.c" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/$(KM_NAME)/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

all: $(OBJ)
	$(LD) $(LDFLAGS) -shared $(OBJ) $(PROJECT_ROOT)/libgcc_$(ARCH).a -o ../../modules-$(ARCH)/$(KM_NAME).ko

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/$(KM_NAME)/%.c.o: %.c GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -I$(shell pwd)/ -I$(shell pwd)/lwip/include -c $< -o $@
