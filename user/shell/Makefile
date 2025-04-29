all:
	$(MAKE) -C pl_readline lib

	$(CC) $(GLOBAL_CFLAGS) -Ipl_readline/include/ -Iflanterm/ -c shell.c -o shell.o
	$(LD) $(LDFLAGS) shell.o pl_readline/libplreadln.a $(ROOT_DIR)/libc/lib/lib*.a $(ROOT_DIR)/libc/lib/crt*.o -o $(SYSROOT)/bin/shell.exec	

clean:
	rm -rf *.o *.exec
