all:
	$(MAKE) -C pl_readline clean
	$(MAKE) -C pl_readline lib

	$(CC) $(GLOBAL_CFLAGS) -Ipl_readline/include/ -c shell.c -o shell.o
	$(LD) $(LDFLAGS) shell.o pl_readline/libplreadln.a -o $(SYSROOT)/bin/shell.elf	

clean:
	rm -rf *.o *elf
