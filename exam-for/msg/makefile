SRC=va_list.c
obj=va_list.o
all: va_list va_test
CC=gcc
va_test: va_list.c va_list.h
	$(CC) $(SRC) -o va_test -D__TEST__MAIN__ -D__MSG__DEBUG__
va_list: va_list.c va_list.h
	$(CC) $(SRC) -c
	ar cr libvalist.a $(obj)
clean:
	rm -rf *.o va_test lib* 
