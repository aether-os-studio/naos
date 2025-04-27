export CC := $(ARCH)-linux-gnu-gcc
export LD := $(ARCH)-linux-gnu-ld
export CWD = $(shell pwd)
export GLOBAL_CFLAGS = -static -nostdinc -nostdlib -mno-red-zone -fno-builtin -fno-stack-protector -g -O0 -I$(CWD)/aelibc/include

all:
	$(MAKE) -C aelibc

	$(MAKE) -C init
	$(MAKE) -C shell

.PHONY: clean
clean:
	rm -rf obj/

.PHONY: distclean
distclean:
