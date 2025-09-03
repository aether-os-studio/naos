export CWD = $(shell pwd)
export SYSROOT = $(CWD)/rootfs-$(ARCH)

MIRROR ?= https://mirrors.tuna.tsinghua.edu.cn/voidlinux/current/musl

all:
	sh ports.sh

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf xbps-bin xbps
	rm -rf .build-stamp-*
	sudo rm -rf $(CWD)/rootfs-$(ARCH)
	rm -rf $(CWD)/ports/cache
