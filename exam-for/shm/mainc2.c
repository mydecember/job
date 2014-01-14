#include"shm.h"
#include"stdio.h"
#include"pthread.h"
#include <sys/mman.h>
#include"fcntl.h"
#include"unistd.h"
#include"loopbuf.h"
void my_lock_init(UC_ShmMemory*  p)
{
	sem_init(&p->sem,1,ROW);
}
 

void my_lock_wait(UC_ShmMemory*  p)
{
//pthread_mutex_lock(&p->mptr);
sem_wait(&p->sem);
}

void my_lock_release(UC_ShmMemory*  p)
{
//pthread_mutex_unlock(&p->mptr);
sem_post(&p->sem);
}
//get array two
/*void** malloc2d(int line, int col,int unitsize)
{
	int i;
	int col_size=col*unitsize;
	int index_size=line*sizeof(void*);
	void **a=(void**)malloc(index_size+line*col_size);
	char *data_start=(char*)a+index_size;
	for(i=0;i<line;++i)
	a[i]=data_start+i*col_size;
	return a;
}*/
int init_loop(struct loopbuf** loop,int *shmid,char *shmpath,int id){ 
//	int shmid;
		*shmid=CreateShm(shmpath,id,sizeof(UC_ShmMemory));
		*loop=(UC_ShmMemory*)AttachShm(*shmid);
	
		//my_lock_init(*loop);

	(*loop)->looplen=ROW;
	(*loop)->buflen=COL;
	(*loop)->tail=0;
	(*loop)->head=0;
	printf("aaa\n");
	return 1;
	//sem_init(&loop->sem,0,0);
//	memset(loop->recvlen,0,MAX_RECV_QUEUE*sizeof(int));
	
//	loop->p=(char**)malloc2d(row,col,typelen);	
	
}
int destroy_loop(struct loopbuf* loop){
	//free(loop->p);
	DetachShm(loop);
	return 1;
}
/*	int main()
	{
		
		int n;
		int shmid;
		shmid=CreateShm("/home",4,sizeof(UC_ShmMemory));
		p=(UC_ShmMemory*)AttachShm(shmid);
			printf("ccccccccccc\n");
		my_lock_init(p,NULL);
		printf("aaaaaaaaaaaa\n");
		//printf("input:");
	//	scanf("%d",&n);
		//p->CurFileNum=n;
	//	printf("%d\n",p->CurFileNum);
		//sleep(10);
	//	scanf("%d",&n);
	
	while(p->CurFileNum==0)
	my_lock_wait(p);
	//my_lock_wait(p);
	printf("nnnnnnnnnnnn\n");
	printf("%d\n",p->CurFileNum);
		DetachShm(p);
		//DeleteShm(shmid);
		
	}*/
		int main()
	{
		
		UC_ShmMemory *p=NULL;
		int n;
	int shmid;
	//	shmid=CreateShm("/home",4,sizeof(UC_ShmMemory));
	//	p=(UC_ShmMemory*)AttachShm(shmid);
	//	my_lock_init(p,NULL);
	//	printf("input:");
	printf("%d\n",sizeof(UC_ShmMemory));
	init_loop(&p,&shmid,"/home/zhao",26);
printf("%d\n",shmid);
	//	scanf("%d",&n);

		if(!p)
			printf("pppppppppp\n");
//	p->head=n;
	//while(p->head==0)
	//my_lock_wait(p);
	while(1)
	{
	
	my_lock_wait(p);
		printf("%d\n",p->head);
		//	my_lock_release(p);
	if(p->head==-1)
		break;
}		
		destroy_loop(p);
	//	DeleteShm(shmid);

	return 1;
		
	}