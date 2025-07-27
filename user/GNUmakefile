export CWD = "$(shell pwd)"

all:
	mkdir -p rootfs-$(ARCH)

	./build-support/setup.sh

	./jinx build-if-needed base $(PKGS)
	./jinx install rootfs-$(ARCH) base $(PKGS)

	cp -r build-support/profile rootfs-$(ARCH)/etc
	cp -r build-support/passwd rootfs-$(ARCH)/etc
	cp -r build-support/group rootfs-$(ARCH)/etc
	cp -r build-support/shells rootfs-$(ARCH)/etc
	cp -r build-support/bash/* rootfs-$(ARCH)/etc
	mkdir -p rootfs-$(ARCH)/run/
	cp -r build-support/weston/udev rootfs-$(ARCH)/run

	mkdir -p rootfs-$(ARCH)/tmp
	mkdir -p rootfs-$(ARCH)/run
	mkdir -p rootfs-$(ARCH)/var

	mkdir -p rootfs-$(ARCH)/root
	cp -r build-support/root/* rootfs-$(ARCH)/root

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf .build-stamp-*
	rm -rf $(CWD)/rootfs-$(ARCH)
