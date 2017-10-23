CC=gcc
CFLAGS=-O3
LFLAGS=-lmath
 
all:
	$(CC) $(CFLAGS) netsechw2.c -lpcap -o mydump

clean:
	$(RM) mydump
