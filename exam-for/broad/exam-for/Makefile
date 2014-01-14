all: call 
call:call.c deltans.c
	gcc call.c deltans.c -o call -lrt -lpcap  -DHAVE_PF_RING -L./ -ltop
clean:
	rm -rf *.o udps udpcc udpc call *.bak pfcount
