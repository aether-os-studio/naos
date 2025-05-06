export LD = ld.lld
export CWD = $(ROOT_DIR)/user
ifeq ($(ARCH), x86_64)
export GLOBAL_CFLAGS = -static -Wno-attributes -nostdlib -mno-red-zone -fno-builtin -fno-stack-protector -g3 -O0 -I$(ROOT_DIR)/libc-$(ARCH)/include/
endif
ifeq ($(ARCH), aarch64)
export GLOBAL_CFLAGS = -static -nostdlib -fno-builtin -fno-stack-protector -g3 -O0 -I$(ROOT_DIR)/libc-$(ARCH)/include/
endif
export CFLAGS = $(GLOBAL_CFLAGS)
export LDFLAGS = -static -nostdlib $(ROOT_DIR)/libc-$(ARCH)/lib/crt0.o $(ROOT_DIR)/libc-$(ARCH)/lib/crti.o $(ROOT_DIR)/libc-$(ARCH)/lib/crtn.o $(ROOT_DIR)/libc-$(ARCH)/lib/lib*.a
export SYSROOT = $(CWD)/usr-$(ARCH)

all:
	rm -rf $(SYSROOT)

	mkdir -p $(SYSROOT)/bin

	$(MAKE) -C init
	$(MAKE) -C shell
	$(MAKE) -C min0911

ifeq ($(ARCH), x86_64)
	$(MAKE) -C test_glibc
endif

.PHONY: clean
clean:
	rm -rf obj/
	rm -rf $(SYSROOT)

.PHONY: distclean
distclean:
