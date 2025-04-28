all:
	$(MAKE) -C pl_readline lib

	$(CC) $(GLOBAL_CFLAGS) -Ipl_readline/include/ -Iflanterm/ -c shell.c -o shell.o
	$(LD) shell.o pl_readline/libplreadln.a $(shell find $(CWD)/obj/ -name "*.o") -o shell.exec	

clean:
	rm -rf *.o *.exec
