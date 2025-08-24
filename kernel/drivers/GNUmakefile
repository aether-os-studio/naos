export CFLAGS := -g3 -O0 -fno-stack-protector -Wno-address-of-packed-member -fvisibility=hidden -fPIC -fno-builtin -nostdinc -nostdlib -I$(shell pwd)/../src/ -I$(shell pwd)/../freestnd-c-hdrs/

all:
	mkdir -p ../drivers-$(ARCH)

	$(MAKE) -C ahci
	$(MAKE) -C nvme
	$(MAKE) -C usb
	$(MAKE) -C virtio
	$(MAKE) -C ext
