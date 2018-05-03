CC=gcc
CFLAGS=-fno-stack-protector -w

all: shell badcode badcode_dep

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

badcode: badcode.o
	$(CC) $(CFLAGS) -o badcode badcode.c
	execstack -s ./badcode

badcode_dep: badcode.o
	$(CC) $(CFLAGS) -o badcode_dep badcode.c
	execstack -c ./badcode_dep

shell: shell.o
	$(CC) -o shell shell.c

clean: 
	rm -f *.o badcode badcode_dep shell
