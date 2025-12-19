export CWD = $(shell pwd)
export SYSROOT = $(CWD)/initramfs-$(ARCH)

all:
	sh ports.sh
ifeq ($(ARCH), x86_64)
# 	sh get_nvidia_firmware.sh
endif

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf xbps-bin xbps
	rm -rf .build-stamp-*
	sudo rm -rf $(CWD)/initramfs-$(ARCH)
	rm -rf $(CWD)/ports/cache
