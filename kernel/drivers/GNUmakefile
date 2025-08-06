export CFLAGS := -Wno-address-of-packed-member -fPIC -fno-builtin -nostdinc -nostdlib -I$(shell pwd)/../src/ -I$(shell pwd)/../freestnd-c-hdrs/

all:
	mkdir -p ../drivers-$(ARCH)

	$(MAKE) -C nvme
	$(MAKE) -C usb
