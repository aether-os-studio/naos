export CWD = $(shell pwd)
export SYSROOT = $(CWD)/rootfs-$(ARCH)/usr

all:
	mkdir -p $(SYSROOT)/bin

ifeq ($(ARCH), x86_64)
	sh ports/ports.sh
endif

.PHONY: clean
clean:
	rm -rf $(SYSROOT)/../

.PHONY: distclean
distclean:
