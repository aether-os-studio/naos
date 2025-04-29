all:
	$(CC) $(GLOBAL_CFLAGS) -c init.c -o init.o
	$(LD) $(LDFLAGS) init.o $(ROOT_DIR)/libc/lib/lib*.a $(ROOT_DIR)/libc/lib/crt*.o -o init.exec
