//name:loopbuf.h
#ifndef __LOOP_BUF__
#define __LOOP_BUF__
#include <semaphore.h>
#include <sys/time.h>
#include"pthread.h"
#include"semaphore.h"

#define COL 3000
#define ROW 1000
#define  MAX_RECV_QUEUE ROW
typedef struct loopbuf{
//	 pthread_mutex_t mptr;
	char data[ROW][COL];
	int looplen;
	int buflen;
	int head;
	int tail;
	sem_t sem;
	int proc; 
	unsigned int recvlen[MAX_RECV_QUEUE];
	struct timeval ts[MAX_RECV_QUEUE];	
	
}UC_ShmMemory;
//extern int getpacket(struct loopbuf* loop,int * exitflag);
//int init_loop(struct loopbuf* loop,int *shmid,char *shmpath);
int init_loop(struct loopbuf** loop,int *shmid,char *shmpath,int id);
extern int destroy_loop(struct loopbuf* loop);
void my_lock_release(UC_ShmMemory*  p);
#endif
