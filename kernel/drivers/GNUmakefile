export CFLAGS := -Wno-address-of-packed-member -fvisibility=hidden -Wl,-z,now -fPIC -fno-builtin -nostdinc -nostdlib -I$(shell pwd)/../src/ -I$(shell pwd)/../freestnd-c-hdrs/

all:
	mkdir -p ../drivers-$(ARCH)

	$(MAKE) -C nvme
	$(MAKE) -C usb
	$(MAKE) -C ext
