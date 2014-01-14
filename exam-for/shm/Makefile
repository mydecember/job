all: mainc mains libshm mainc2
mainc: mainc.c shm.c
	gcc mainc.c shm.c -o mainc -lpthread
mainc2: mainc2.c shm.c
	gcc mainc2.c shm.c -o mainc2 -lpthread
mains: mains.c shm.c
	gcc mains.c shm.c -o mains -lpthread -Wall -D__TEST__MAINS__
libshm: mains.c shm.c
	gcc mains.c shm.c -c 
	ar cr libshm.a mains.o shm.o 
	
clean:
	rm -rf *.o mainc mians mainc2