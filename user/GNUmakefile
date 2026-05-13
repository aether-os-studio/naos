export CWD = $(shell pwd)
export SYSROOT = $(CWD)/initramfs-$(ARCH)
export ROOTFS_SYSROOT = $(CWD)/rootfs-$(ARCH)

all:
	sh build_initramfs.sh
ifeq ($(ARCH), x86_64)
endif
	sh build_rootfs.sh

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf cache
	rm -rf .build-stamp-*
	sudo rm -rf $(CWD)/initramfs-$(ARCH) $(CWD)/rootfs-$(ARCH)
	rm -rf $(CWD)/ports/cache
