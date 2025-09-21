CFLAGS := -g3 -O0 -fno-stack-protector -Wno-address-of-packed-member -fvisibility=hidden -fPIC -fno-builtin -nostdinc -nostdlib -I$(shell pwd)/../kernel/src -I$(shell pwd)/../kernel/freestnd-c-hdrs
export CFLAGS

all:
	mkdir -p ../modules-$(ARCH)

	$(MAKE) -C ahci
	$(MAKE) -C nvme
	$(MAKE) -C usb
	$(MAKE) -C e1000
	$(MAKE) -C virtio
	$(MAKE) -C vmware_svga
	$(MAKE) -C nvidia_open

	$(MAKE) -C ext

	$(MAKE) -C netserver

	$(MAKE) -C hid
	$(MAKE) -C msc
