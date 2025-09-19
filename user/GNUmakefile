export CWD = $(shell pwd)
export SYSROOT = $(CWD)/rootfs-$(ARCH)

all:
	sh ports.sh
	sh get_nvidia_firmware.sh
	$(MAKE) -C init

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf xbps-bin xbps
	rm -rf .build-stamp-*
	sudo rm -rf $(CWD)/rootfs-$(ARCH)
	rm -rf $(CWD)/ports/cache
