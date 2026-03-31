all:
ifeq ($(ARCH), x86_64)
	$(MAKE) -C e1000
ifneq ($(BUILD_NVIDIA), 0)
	$(MAKE) -C nvidia_open
endif
endif

	$(MAKE) -C sound

	$(MAKE) -C nvme

	$(MAKE) -C usb
	$(MAKE) -C virtio

	$(MAKE) -C hub
	$(MAKE) -C hid
	$(MAKE) -C msc

	$(MAKE) -C mt7921
