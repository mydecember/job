CC=gcc
TARGET=all

all:acsmx libacsm main

acsmx:entry.c acsmx.c deltans.c
	$(CC)  -o $@ $^ -lrt
main: libacsm main.c deltans.c
	$(CC) main.c deltans.c -L. -lacsm -o main -lrt
libacsm:
	$(CC) -c acsmx.c
	ar cr libacsm.a acsmx.o 


clean:
	rm -rf acsmx *.a *.o
