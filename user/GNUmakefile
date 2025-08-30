export CWD = "$(shell pwd)"
export SYSROOT = $(CWD)/rootfs-$(ARCH)

MIRROR ?= https://mirrors.tuna.tsinghua.edu.cn/voidlinux/current/musl

all: xbps-bin
	sudo XBPS_ARCH=$(ARCH)-musl xbps-bin/usr/bin/xbps-install --repository=$(MIRROR) -r $(SYSROOT) -S base-minimal bash gcc binutils lua curl evtest xinit xorg-server xf86-input-evdev xf86-video-fbdev dina-font xsetroot st twm xeyes $(PKGS)
	sudo cp -r base/* $(SYSROOT)/

xbps-bin:
	sh build_xbps.sh

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf xbps-bin xbps
	rm -rf .build-stamp-*
	sudo rm -rf $(CWD)/rootfs-$(ARCH)
	rm -rf $(CWD)/ports/cache
