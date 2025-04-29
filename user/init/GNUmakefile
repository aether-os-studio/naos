all:
	$(CC) $(GLOBAL_CFLAGS) -c init.c -o init.o
	$(LD) init.o $(ROOT_DIR)/libc/lib/libc.a $(ROOT_DIR)/libc/lib/libm.a -o init.exec
