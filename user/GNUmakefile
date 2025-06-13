export CWD = $(shell pwd)
export SYSROOT = $(CWD)/rootfs-$(ARCH)/usr

all:
	mkdir -p $(SYSROOT)/bin
	sh ports/ports.sh

.PHONY: clean
clean:
	rm -rf .build-stamp

.PHONY: distclean
distclean:
	rm -rf $(CWD)/rootfs-$(ARCH)
	rm -rf $(CWD)/ports/cache
