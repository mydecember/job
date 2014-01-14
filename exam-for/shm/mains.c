#include"shm.h"
#include"stdio.h"
#include <sys/mman.h>
#include"pthread.h"
#include"fcntl.h"
#include"loopbuf.h"
#include"string.h"
#include"signal.h"
static int exitflag=0;
static void sigproc(int sig) {
	
exitflag=1;


		
  //pcap_breakloop();
}
void my_lock_init(UC_ShmMemory*  p)
{
	if(sem_init(&p->sem,1,0)==-1)
		perror("init error\n");
}
 

void my_lock_wait(UC_ShmMemory*  p)
{
//pthread_mutex_lock(&p->mptr);
if(sem_wait(&p->sem)==-1)
	perror("wait error\n");
}

void my_lock_release(UC_ShmMemory*  p)
{
//pthread_mutex_unlock(&p->mptr);
if(sem_post(&p->sem)==-1)
	perror("post error\n");
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
		printf("shmpath=%s\nshmid=%d\n",shmpath,*shmid);
		memset(*loop,0,sizeof(UC_ShmMemory));
		if(*loop==NULL)
			printf("open error\n");
	
		my_lock_init(*loop);

	(*loop)->looplen=ROW;
	(*loop)->buflen=COL;
	(*loop)->tail=0;
	(*loop)->head=0;
	(*loop)->proc=0;
	printf("aaa\n");
	return 1;
	//sem_init(&loop->sem,0,0);
//	memset(loop->recvlen,0,MAX_RECV_QUEUE*sizeof(int));
	
//	loop->p=(char**)malloc2d(row,col,typelen);	
	
}
int destroy_loop(struct loopbuf* loop){
	//free(loop->p);
//	sem_destroy(&loop->sem);
	DetachShm(loop);
	return 1;
}

#ifdef __TEST__MAINS__
	int main()
	{
		UC_ShmMemory *p=NULL;//////////////////////////
			UC_ShmMemory *p2=NULL;//////////////////////////
		int n;
		char *shmpath="/tmp/uu";
		char *shmpath2="/home/zhao";
	int shmid;////////////////////////////////////////////////
	int shmid2;
	//	shmid=CreateShm("/home",4,sizeof(UC_ShmMemory));
	//	p=(UC_ShmMemory*)AttachShm(shmid);
		//my_lock_init(p,NULL);
		printf("input:");
	printf("%d\n",sizeof(UC_ShmMemory));
	init_loop(&p,&shmid,shmpath,4);
		init_loop(&p2,&shmid2,shmpath2,26);
	if(!p||!p2)
			printf("pppppppppp\n");
			int cout=0;
			int i;
			int flag=0;
			signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);
  int semnum;
  sem_getvalue(&p->sem,&semnum);
  printf("semnum:%d\n",semnum);
  sleep(4);
  
			while(1)
			{

		//scanf("%d",&n);
		n=45;
	if(cout%2==0)
	{
		//	my_lock_wait(p);
		p->head=n;
	 	my_lock_release(p);
	 //	sem_getvalue(&p->sem,&semnum);
//  printf("semnum:%d\n",semnum);
	}
	else
		{
			//my_lock_wait(p2);
				p2->head=n;
	 	my_lock_release(p2);
	// 	sem_getvalue(&p2->sem,&semnum);
 // printf("semnum:%d\n",semnum);
		}
	 cout++;
	 if(exitflag==1)
	 	{
	 		p->head=-1;
	 	my_lock_release(p);
	 	p2->head=-1;
	 	my_lock_release(p2);
	 	}

		//printf("%d\n",p->head);
	if(p->head==-1||p2->head==-1)
			flag++;
			if(flag==2)
				break;
	}
	
		//	scanf("%d",&n);
		
		sleep(1);
		//DetachShm(p);
		destroy_loop(p);
	
		destroy_loop(p2);
			DeleteShm(shmid);
		DeleteShm(shmid2);
	return 1;
		
	}
#endif
/*	int main()
	{
		UC_ShmMemory *p;
		int n;
		int shmid;
		shmid=CreateShm("/home",4,sizeof(UC_ShmMemory));
		p=(UC_ShmMemory*)AttachShm(shmid);
		my_lock_init(p,NULL);
	//	printf("input:");
		scanf("%d",&n);
	p->buflen=n;
		printf("%d\n",p->buflen);
		//	scanf("%d",&n);
		 my_lock_release(p);
		DetachShm(p);
		DeleteShm(shmid);
		
	}*/