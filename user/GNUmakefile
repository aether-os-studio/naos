export CWD = $(ROOT_DIR)/user
ifeq ($(ARCH), x86_64)
export GLOBAL_CFLAGS = -static -nostdlib -mno-red-zone -fno-builtin -fno-stack-protector -g3 -O0 -I$(ROOT_DIR)/libc-$(ARCH)/include/
endif
ifeq ($(ARCH), aarch64)
export GLOBAL_CFLAGS = -static -nostdlib -fno-builtin -fno-stack-protector -g3 -O0 -I$(ROOT_DIR)/libc-$(ARCH)/include/
endif
export CFLAGS = $(GLOBAL_CFLAGS)
export LDFLAGS = -static -nostdlib
export SYSROOT = $(CWD)/usr-$(ARCH)

all:
	mkdir -p $(SYSROOT)/bin

	$(MAKE) -C init
	$(MAKE) -C shell

.PHONY: clean
clean:
	rm -rf obj/
	rm -rf $(SYSROOT)

.PHONY: distclean
distclean:
