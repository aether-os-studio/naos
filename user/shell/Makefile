all:
	$(MAKE) -C pl_readline lib

	$(CC) $(GLOBAL_CFLAGS) -Ipl_readline/include/ -Iflanterm/ -I$(CWD)/apps/aeui -c shell.c -o shell.o
	ld shell.o pl_readline/libplreadln.a $(shell find $(CWD)/obj/ -name "*.o") -o shell.exec	

clean:
	rm -rf *.o *.exec
