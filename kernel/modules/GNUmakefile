CFLAGS := -g3 -O0 -fno-stack-protector -Wno-address-of-packed-member -fvisibility=hidden -fPIC -fno-builtin -nostdinc -nostdlib -I$(shell pwd)/../src -I$(shell pwd)/../freestnd-c-hdrs
export CFLAGS

all:
	mkdir -p ../modules-$(ARCH)

	$(MAKE) -C ahci ARCH=$(ARCH) CFLAGS="$(CFLAGS)"
	$(MAKE) -C nvme ARCH=$(ARCH) CFLAGS="$(CFLAGS)"
	$(MAKE) -C usb ARCH=$(ARCH) CFLAGS="$(CFLAGS)"
	$(MAKE) -C virtio ARCH=$(ARCH) CFLAGS="$(CFLAGS)"
	$(MAKE) -C ext ARCH=$(ARCH) CFLAGS="$(CFLAGS)"
