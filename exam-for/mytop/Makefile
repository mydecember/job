SRC:=m_linux.c utils.c mytop.c
OBJS:=m_linux.o utils.o mytop.o
all: mytop libtop.a testlib
mytop:${OBJS}
	gcc ${SRC} -o $@ -D__TEST__
libtop.a:${OBJS}
	gcc ${SRC} -c 
	ar cr libtop.a ${OBJS}
testlib:libtop.a test.c
	gcc  test.c   -o test -L./ -ltop 
clean:
	rm -rf *.o mytop main test libtop.alin
