export CWD = $(shell pwd)
export SYSROOT = $(CWD)/rootfs-$(ARCH)/usr

all:
	mkdir -p $(SYSROOT)/bin

	sh ports/ports.sh

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf $(CWD)/rootfs-$(ARCH)
