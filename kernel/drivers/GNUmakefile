export CFLAGS := -fPIC -fno-builtin -nostdinc -m64 -I$(shell pwd)/../src/ -I$(shell pwd)/../freestnd-c-hdrs/

all:
	mkdir -p ../drivers-$(ARCH)

	$(MAKE) -C xhci_hcd	
