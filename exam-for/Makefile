all:
	cd ac;make
	cd msg;make
	cd shm;make
	cd mytop;make
	make -f Makefile-load
	make -f Makefile-call
	


	
clean:
	make -f Makefile-load clean
	cd msg;make clean
	cd ac;make clean
	cd shm;make clean
	cd mytop;make clean
	make -f Makefile-call clean

