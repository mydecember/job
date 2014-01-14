all: serverUDP client
serverUDP:serverUDP.c deltans.c
	gcc serverUDP.c deltans.c -o serverUDP -lrt
client:client.c deltans.c
	gcc client.c deltans.c -o client -lrt
clean:
	rm -rf *.o  serverUDP *.bak
