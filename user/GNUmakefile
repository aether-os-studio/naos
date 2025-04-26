export CC := $(ARCH)-linux-gnu-gcc
export LD := $(ARCH)-linux-gnu-ld
export CWD = $(shell pwd)
export GLOBAL_CFLAGS = -static -nostdinc -nostdlib -mno-red-zone -fno-builtin -fno-stack-protector -g -O0 -I$(CWD)/aelibc/include

all:
	$(MAKE) -C aelibc

	$(MAKE) -C init

.PHONY: clean
clean:

.PHONY: distclean
distclean:
