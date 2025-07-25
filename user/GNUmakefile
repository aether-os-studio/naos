export CWD = $(shell pwd)

all:
	./build-support/setup.sh

	./jinx build-if-needed base $(PKGS)
	./jinx install rootfs-$(ARCH) base $(PKGS)

	mkdir -p rootfs-$(ARCH)/root

	cp build-support/profile rootfs-$(ARCH)/etc
	cp build-support/passwd rootfs-$(ARCH)/etc
	cp build-support/group rootfs-$(ARCH)/etc
	cp build-support/shells rootfs-$(ARCH)/etc
	cp build-support/bash/* rootfs-$(ARCH)/etc

.PHONY: clean
clean:

.PHONY: distclean
distclean:
	rm -rf .build-stamp-*
	rm -rf $(CWD)/rootfs-$(ARCH)
