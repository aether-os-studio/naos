export CC := $(ARCH)-linux-gnu-gcc
export LD := $(ARCH)-linux-gnu-ld
export CWD = $(ROOT_DIR)/user
export GLOBAL_CFLAGS = -static -nostdlib -mno-red-zone -fno-builtin -fno-stack-protector -g3 -O0 -I$(ROOT_DIR)/libc/include/

all:
	$(MAKE) -C init
	$(MAKE) -C shell

.PHONY: clean
clean:
	rm -rf obj/

.PHONY: distclean
distclean:
