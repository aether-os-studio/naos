all:
	$(CC) $(GLOBAL_CFLAGS) -c init.c -o init.o
	$(LD) init.o $(shell find $(CWD)/obj/ -name "*.o") -o init.exec
