export CWD = $(shell pwd)
export SYSROOT = $(CWD)/rootfs-$(ARCH)

all:
	sh ports.sh
ifeq ($(ARCH), x86_64)
ifneq ($(BUILD_NVIDIA), 0)
	sh get_nvidia_firmware.sh
endif
endif

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf xbps-bin xbps
	rm -rf .build-stamp-*
	sudo rm -rf $(CWD)/rootfs-$(ARCH)
	rm -rf $(CWD)/ports/cache
