all:
	$(MAKE) -C pl_readline clean
	$(MAKE) -C pl_readline lib

	$(CC) $(GLOBAL_CFLAGS) -Ipl_readline/include/ -c shell.c -o shell.o
	$(LD) $(LDFLAGS) shell.o pl_readline/libplreadln.a $(ROOT_DIR)/libc-$(ARCH)/lib/lib*.a $(ROOT_DIR)/libc-$(ARCH)/lib/crt*.o -o $(SYSROOT)/bin/shell.exec	

clean:
	rm -rf *.o *.exec
