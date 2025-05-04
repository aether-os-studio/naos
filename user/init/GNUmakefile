all:
	$(CC) $(GLOBAL_CFLAGS) -c init.c -o init.o
	$(LD) $(LDFLAGS) init.o $(ROOT_DIR)/libc-$(ARCH)/lib/lib*.a $(ROOT_DIR)/libc-$(ARCH)/lib/crt*.o -o $(SYSROOT)/bin/init.exec
