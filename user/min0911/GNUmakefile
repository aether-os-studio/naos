all:
	$(CC) $(GLOBAL_CFLAGS) -c min0911.c -o min0911.o
	$(LD) $(LDFLAGS) min0911.o $(ROOT_DIR)/libc-$(ARCH)/lib/lib*.a $(ROOT_DIR)/libc-$(ARCH)/lib/crt*.o -o $(SYSROOT)/bin/min0911.exec
