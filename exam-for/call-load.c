#include <stdio.h>
#include"unistd.h"
#include <stdlib.h>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include"fcntl.h"
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>

#include <linux/icmp.h>

#include <netinet/ip.h>//ipÍ· 
#include <netinet/tcp.h>//ipÍ· 
#include <net/ethernet.h>//ether_header macÍ·
#include"linux/if_ether.h"
#include <sys/un.h>
#include"errno.h"

#include <net/if.h>
#include<netinet/udp.h>
#include <netdb.h>
#include"deltans.h"
#include"load.h"
#include"time.h"
#include"shm/loopbuf.h"
#include"shm/shm.h"
#include"ac/acsmx.h"
#include"mytop/top.h"

#define  snortnum 1
#define SEND_NUM 1
#define ALARM_SLEEP 1
extern  int get_sys_info(float *sysinfo,int n);

static char pro_map[PRO_MAX+2][20]={"HTTP","FTP","POP3","SMTP","UNKOWN","UDP","ICMP"};
static long long pronum[PRO_MAX+2]={0LL};
char shmpath[20]="/home";
int flag=0;
int firstlen;
NS_TIME(time);
int n=0;
int b=0;
float f[60][10];
int alarmnum=0;

UC_ShmMemory *shmp[snortnum];

//char *shmpath="/tmp/uu";
//char *shmpath1="/tmp/uu1";
//int shmid;
long long losep[snortnum]={0LL};


int shmid[snortnum];
//char *shmpath[snortnum];
int exitflag=0;
int size_mac;
int size_ip;

pcap_dumper_t *out_pcap;
///////////acsmx//////////////
extern ACSM_STRUCT * acsm;
long long  packet_num=0;
long long packet_len=0;
HB* hb;

int nocase = 0;
unsigned char text[MAXLEN]="wetwe http sdfsd";
long long find_pro=0LL;
//////////////////////////
////////////////////////

 struct ether_header *mac=NULL;
    struct ip* ip=NULL;
    struct fniff_tcp * tcp;
    struct icmphdr* icmp;
    struct udphdr* udp;
//////////////////////////
#define BC_CLASS_NUM 1000
typedef struct bc_class{
	BC* BCbuf[BC_CLASS_NUM];
	int tail;
	int head;	
}BCC;
struct bc_class bcbuf;
sem_t bin_sem;
void initBCBuff()
{
	memset(&bcbuf,0,sizeof(BCC));
	bcbuf.tail=0;bcbuf.head=0;
	
	int res = sem_init(&bin_sem, 0, 0);
 if (res < 0)
 {
  printf("Semaphore initialization failed");
 }
}

long long TCP_num=0;

void my_sigalarm(int sig) {
  //if(do_shutdown)
   // return;
get_sys_info(f[alarmnum],10);
alarmnum++;
//printf("vvvvvvvvvvv\n");
  //print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

void sigproc(int sig) {
int i;
long long sum=0;
/*for(i=0;i<snortnum;++i)
	{printf("\nlosep[%d]=%lld\n",i,losep[i]);
	sum+=losep[i];
	printf("%d,%d\n",shmp[i]->tail,shmp[i]->head);
	}
	printf("sum=%lld\n",sum);
	//printf("%d,%d\n",shmp->tail,shmp->head);*/
	exitflag=1;
	for(i=0;i<PRO_MAX+2;++i)
	{
	
	printf("%s:%lld\n",pro_map[i],pronum[i]);
  	 }
   printf("TCP:%ld\n",TCP_num);

		
  //pcap_breakloop();
}

SSDD sd;
int tcplen;
int fin;
int ack;
int syn;
int rst;
unsigned short hash;
SN* temp;

int datalen;
 
unsigned char* ptcp;
static BC *p;
long long losepacket=0;

int high_level=64*1024*0.8;

int session_num[65536]={0};

#define process_num 7
#define queue_LEN 4096
pthread_mutex_t work_mutex[process_num];

int mypipe[process_num][2];
typedef struct queue{
	int all[process_num];
	int queueState[process_num][queue_LEN];
	int h[process_num];
	int t[process_num];
	int queue_len[process_num];
	int session[process_num];
	//int session_end
}queue_t;
queue_t state;

int pop(int num)
{
	 pthread_mutex_lock(&work_mutex[num]);  
	if(state.t[num]!=state.h[num])
	{
		int tmp=state.h[num];
		state.h[num]=(state.h[num]+1)%queue_LEN;
		state.queue_len[num]=(state.all[num])*0.5+(state.all[num]-state.queueState[num][tmp])*0.5;		
		state.all[num]-=state.queueState[num][tmp];
		
		 pthread_mutex_unlock(&work_mutex[num]);  
		return state.queueState[num][tmp];
	}
	pthread_mutex_unlock(&work_mutex[num]);  
	return -1;
}
int push(int num,int n)
{
	 pthread_mutex_lock(&work_mutex[num]);  
	int tmp=state.t[num];
	if((tmp+1)%queue_LEN==state.h[num])
	{
		 pthread_mutex_unlock(&work_mutex[num]);  
		return -1;
	}
	state.queueState[num][state.t[num]]=n;
	
	state.all[num]+=n;
	state.t[num]=(tmp+1)%queue_LEN;
	state.queue_len[num]=state.all[num]*0.5+(state.all[num]-n)*0.5;
	pthread_mutex_unlock(&work_mutex[num]);  
	return n;
}
int now_num=0;

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	packet_num++;
	packet_len+=pkthdr->caplen;

    static   int count = 0;
	//static int nn=0;
	static int i;
	static unsigned short eth_type;
	static int vlan_flag=0;
		//sem_getvalue(&shmp[i]->sem,&semnum);
		//printf("sem:%d\n",semnum);		
	//usleep(1000);
int semnum;
//	sem_getvalue(&bin_sem,&semnum);
	//	printf("sem:%d\n",semnum);
		//printf("mmmmmmmmmmmmmm\n");
		if(exitflag)
		{
	   		printf("losepacket=%lld\n",losepacket);			
			 NS_TIME_END(time);			
			speed1(NS_GET_TIMEP(time),packet_num,packet_len);
			printf("count=%d,\nfind_pro=%lld\n",count,find_pro);
				
			del_HB(&hb);		
			acsmFree (acsm);
	
			exit(0);
		} 
//return;
		#if 1
		 mac=(struct ether_header*)packet;
		 eth_type=ntohs(mac->ether_type);
		
		 if((eth_type==0x8100))
		 {
		 	vlan_flag=1;
		 	//msg("W:****0X%04X\n",eth_type);
		 	eth_type=(packet[16])*256+packet[17];
		 }
		 else
		 	vlan_flag=0;
		
		// msg("W:0X%04X\n",eth_type);
		 if((eth_type!=0x0800))//²»ÊÇipÊýŸÝ±š
		       	return;
		 if(vlan_flag)
		 	ip=(struct ip*)(packet+size_mac+4);
	 	 else
 			ip=(struct ip*)(packet+size_mac);
		#else
		 eth_type=ntohs((uint16_t)(*(uint16_t*)(&packet[2])));
		     //   printf("%04x\n", eth_type);
			ip=(struct ip*)(packet+4);
			size_mac=4;

		#endif

		
		char ipdotdecs[20]={0};
	       char ipdotdecc[20]={0};
		inet_ntop(AF_INET,(void*)&(ip->ip_src),ipdotdecs,16);
			inet_ntop(AF_INET,(void*)&(ip->ip_dst),ipdotdecc,16);
//printf("%s-->%s: len:%d\n",ipdotdecs,ipdotdecc,pkthdr->caplen);

			
		if((ip->ip_p==6))//tcp
		{
			TCP_num++;
			tcp=(struct fniff_tcp*)((char*)ip+size_ip);
			sd.b_ip=(ip->ip_src.s_addr);
			sd.l_ip=(ip->ip_dst.s_addr);
			if(sd.b_ip>sd.l_ip)
			{
				sd.b_port=ntohs(tcp->th_sport);
				sd.l_port=ntohs(tcp->th_dport);
			}
			else
			{
				sd.b_ip^=sd.l_ip;
				sd.l_ip^=sd.b_ip;
				sd.b_ip^=sd.l_ip;
				
				sd.b_port=ntohs(tcp->th_dport);
				sd.l_port=ntohs(tcp->th_sport);					
			}
			
			hash=hash_HB(sd.b_ip,sd.b_port,sd.l_ip,sd.l_port);
			
			tcplen=ntohs(ip->ip_len)-(ip->ip_hl*4)-(tcp->th_off*4);
			  ack=tcp->th_flags&TH_ACK;			
			  rst=tcp->th_flags&TH_RST;
			  syn=tcp->th_flags&TH_SYN;
			  fin=tcp->th_flags&TH_FIN;
		 datalen=pkthdr->caplen;
	   
		ptcp=(unsigned char*)tcp+(tcp->th_off*4);    
		//msg("hb[hash].virtual_sn_num=%d\n",hb[hash].virtual_sn_num); 	
		/*#define MSF 
		#ifdef MSF
			int id=now_num=hash%process_num;
			if(state.queue_len[id]>=high_level)// over load
			{
				
			}
			push(now_num,datalen);
			
		#endif
				*/
		temp=find_node(hb[hash].virtual_sn,&sd);  
	  //msg("ccccc\n");
		if(temp==NULL&&syn&&!ack&&tcplen==0)//not find
	      	{
	      		session_num[hash]++;
			msg("session:%d\n",session_num[hash]);
	      		SN* q=get_node();
	      		q->sdipport=sd;
	      		q->state=1;
			insert_node(&(hb[hash].virtual_sn),q);
			hb[hash].virtual_sn_num++;	
			//session_num[id]++;	
		
	      	}
	      	else if(temp!=NULL)
	      	{
			if((temp->state==1)&&syn&&ack&&(tcplen==0))
	      		{
	      			//msg("W:my ooooooooooooooooooo\n");
	      			temp->state=2;
	      		}
	      		else if(temp->state==2&&ack&&!syn&&tcplen==0)
	      		{
	      			temp->state=3;		      			
	      		}
			else if(temp->state>=3)
		      	{

	      		    			
				i=bcbuf.tail+1;
				if(i==BC_CLASS_NUM)
					i=0;
				if(i==bcbuf.head)
				{      				
					losepacket++;
				}
				else
				{
					bcbuf.BCbuf[bcbuf.tail]=temp->bc_head;
					bcbuf.tail=i;
					push(now_num,datalen);
					write(mypipe[now_num][1],&i,1);
				
				
				}

				if(rst||fin)
				{	
					//session_num[hash]--;	
					temp->bc_head=NULL;
					temp->bc_tail=NULL;	
					temp->state=0;	
					//msg("uuuuuuuuu\n");			
					move_node(&(hb[hash].virtual_sn),temp);
					hb[hash].virtual_sn_num--;
					push(now_num,-1);
			
					//msg("*********=%ld\n",hb[hash].virtual_sn_num);
					if(hb[hash].virtual_sn_num==0)
					{	hb[hash].virtual_sn=NULL;}
				
					return;
				}
			
				
			}
	      		
      		}     	
	    
     }//tcp
     else if(ip->ip_p==1)//icmp
     {
	//printf("2222\n");
     	//static char pro_map[PRO_MAX+2][20]={"HTTP","FTP","POP3","SMTP","UNKOWN","UDP","ICMP"};
 	pronum[PRO_MAX+1]++;
    }
    else if(ip->ip_p==17)//udp
    	{
		//printf("1111111\n");
    		pronum[PRO_MAX]++;
		udp=(struct udphdr *)(packet+size_mac+size_ip);
			sd.b_ip=(ip->ip_src.s_addr);
			sd.l_ip=(ip->ip_dst.s_addr);
			if(sd.b_ip>sd.l_ip)
			{
				sd.b_port=ntohs(udp->source);
				sd.l_port=ntohs(udp->dest);
			}
			else
			{
				sd.b_ip^=sd.l_ip;
				sd.l_ip^=sd.b_ip;
				sd.b_ip^=sd.l_ip;
			
				sd.b_port=ntohs(udp->dest);
				sd.l_port=ntohs(udp->source);				
			}			
			hash=hash_HB(sd.b_ip,sd.b_port,sd.l_ip,sd.l_port);
	    	
    	}   
else
{
	//printf("no\n");
}
}
void threadclass(int ret)
{
	
	int semnum;
//	sem_getvalue(&bin_sem,&semnum);
	//	msg("--******sem:%d\n",semnum);
	msg("ret:%d\n",ret);
	int len;
	while(1)
	{
	
		read(mypipe[(int)ret][0],&semnum,1);
		len=pop(ret);
		if(len==-1)
		{
			session_num[ret]--;
			msg("aaaaaannnnaaaaa\n");
		}
		if(exitflag)
	 	{
	 		 return;
	 	}
		//usleep(5000);
		sleep(1);

	
	}
 
}

void analyze_packet_qqtkt_write1(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//printf("%s\n",&packet[48]);
	//printf("yyyyyyy\n");	
	if(exitflag)
	{
		  int ret = pcap_dump_flush(out_pcap);
		if (ret == -1) {
			
			printf("error in pcap_dump_flush\n");

		}

		pcap_dump_close(out_pcap);
		
		exitflag=0;
		exit(0);
	} 

     	//printf("***\n");
        pcap_dump((unsigned char*)out_pcap, header, packet);

      
}
int set_promisc (char *if_name, int sockfd)
{
    struct ifreq ifr;

    strcpy (ifr.ifr_name, if_name);
    if (0 != ioctl (sockfd, SIOCGIFFLAGS, &ifr))
    {
        printf ("Get interface flag failed\n");
        return -1;
    }

    /* add the misc mode */
    ifr.ifr_flags |= IFF_PROMISC;

    if (0 != ioctl (sockfd, SIOCSIFFLAGS, &ifr))
    {
        printf ("Set interface flag failed\n");
        return -1;
    }
	return 0;
}
//#define __GET__ETH__




#if 0//get packet and write it to the file
int main(int argc, char* argv[])
{

	 char *dev; /* name of the device to use */ 
  char *net; /* dot notation of the network address */
  char *mask;/* dot notation of the network mask    */
  int ret;   /* return code */
 //const u_char *packet;
  pcap_t* descr;      /*you can man it*/
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp; /* ip          */
  bpf_u_int32 maskp;/* subnet mask */
  struct in_addr addr;
 char *bpfFilter="tcp port 21";//NULL;
//	char *bpfFilter=NULL;
char *filename="/dev/shm/get.pcap";
  struct bpf_program fcode;

  /* ask pcap to find a valid device for use to sniff on */
  dev = pcap_lookupdev(errbuf);

  /* error checking */
  if(dev == NULL)
  {
   printf("%s\n",errbuf);
   exit(1);
  }

  /* print out device name */
  printf("DEV: %s\n",dev);

  /* ask pcap for the network address and mask of the device */
  ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

  if(ret == -1)
  {
   printf("%s\n",errbuf);
   exit(1);
  }

  /* get the network address in a human readable form */
  addr.s_addr = netp;
  net = inet_ntoa(addr);

  if(net == NULL)/* thanks Scott :-P */
  {
    perror("inet_ntoa");
    exit(1);
  }

  printf("NET: %s\n",net);

  /* do the same as above for the device's mask */
  addr.s_addr = maskp;
  mask = inet_ntoa(addr);
  
  if(mask == NULL)
  {
    perror("inet_ntoa");
    exit(1);
  }
  
  printf("MASK: %s\n",mask);

 //descr = pcap_open_live(dev,65536,1 ,0,errbuf);
	descr = pcap_open_live(dev,65535,1 ,0,errbuf);
  // descr = pcap_open_live(NULL,BUFSIZ,1 ,0,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

	if(pcap_compile(descr, &fcode, bpfFilter, 1, netp) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(descr));
    } 
	if(pcap_setfilter(descr, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(descr));}

/////////////////////////////
	signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

	
	 out_pcap = pcap_dump_open(descr, filename);
	if (out_pcap == NULL) {
                        printf("ERROR pcap_dump_open \n");
                        exit(-1);
                }
	pcap_loop(descr,-1,analyze_packet_qqtkt_write1,NULL);


	
/////////////////////////////////////////////////////
      
        return 0;
}
#else//read the cap file and call the callback function
int main(int argc, char* argv[])
{

	 char *dev; /* name of the device to use */ 
  char *net; /* dot notation of the network address */
  char *mask;/* dot notation of the network mask    */
  int ret;   /* return code */
 //const u_char *packet;
  pcap_t* descr;      /*you can man it*/
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp; /* ip          */
  bpf_u_int32 maskp;/* subnet mask */
  struct in_addr addr;

  /* ask pcap to find a valid device for use to sniff on */
  dev = pcap_lookupdev(errbuf);

  /* error checking */
  if(dev == NULL)
  {
   printf("%s\n",errbuf);
   exit(1);
  }

  /* print out device name */
  printf("DEV: %s\n",dev);

  /* ask pcap for the network address and mask of the device */
/*  ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

  if(ret == -1)
  {
   printf("%s\n",errbuf);
   exit(1);
  }
*/
  /* get the network address in a human readable form */
//  addr.s_addr = netp;
 // net = inet_ntoa(addr);

 /* if(net == NULL)// thanks Scott :-P 
  {
    perror("inet_ntoa");
    exit(1);
  }

  printf("NET: %s\n",net);

  // do the same as above for the device's mask 
  addr.s_addr = maskp;
  mask = inet_ntoa(addr);
  
  if(mask == NULL)
  {
    perror("inet_ntoa");
    exit(1);
  }*/
  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);
 // printf("MASK: %s\n",mask);
 size_mac=sizeof(struct ether_header);
 size_ip=sizeof(struct ip);
	//char *filename="/dev/shm/get.pcap";
	//char *filename="./get.pcap";
//char *filename="/run/shm/http.pcap";
//initBCBuff();
 pthread_t my_thread[process_num];
for(ret=0;ret<process_num;++ret)
{
	if(pipe(mypipe[ret])<0)
		{
			//perror();
			msg("EIS,pipe error\n");
			exit(0);
		}

	#if 1
	  if(pthread_create(&my_thread[ret], NULL, threadclass, ret)!=0)
	  	{
	  		msg("Ecreate thread error\n");
	  		exit(0);
	  	}
	#endif
}


     /// msg("kkkkkkkkkkkkk\n");
	memset(&state,0,sizeof(queue_t));
	int res;
	for(ret=0;ret<process_num;++ret)
	{	
		res = pthread_mutex_init(&work_mutex[ret], NULL); //init mutex 初始化互斥锁
	    if (res != 0)
	    {
		perror("Mutex initialization failed");
		exit(EXIT_FAILURE);
	    }
	}
int i;
#if 1
	#define MAX_FILE 1
	//char filenameA[MAX_FILE+1][200]={{"/home/zhao/lpls/mytrace.pcap"},{""}};
	//char filenameA[MAX_FILE+1][200]={{"/home/zhao/test/get.pcap"},{""}};
	char filenameA[MAX_FILE+1][200]={{"/run/shm/http.pcap"},{""}};
	//char *filename="./exam-for/ftp.pcap";
	char *filename;
	printf("EIinit hb\n");
	hb=init_HB(HB_MAX);
	init_free_link(FREE_NODE);
	//init_BC();//the cache for the pro classificationd
	printf("EIinit bc\n");
	init_patterns();
 	 NS_TIME_START(time); 
	int num=0;
	int kk=0;
	
again:
	filename= filenameA[num];
//	msg("kk=%d\n",kk);
	num=(num+1)%MAX_FILE;

	
	if(kk==2)
		goto endk;
		++kk;
	descr =pcap_open_offline(filename, errbuf);     
	
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

/////////////////////////////	
	
	pcap_loop(descr,-1,my_callback,NULL);
	//printf("llllllllllllll\n");
	pcap_close(descr);
goto again;
endk:
	NS_TIME_END(time);
	exitflag=1;
	//sem_post(&bin_sem);
	write(mypipe[1],&exitflag,1);
	sleep(2);
	
	printf("TCP:%ld\n",TCP_num);	
	printf("UDP:%ld\n",pronum[PRO_MAX]);
	//speed(NS_GET_TIMEP(time),count+sum,firstlen);
	speed1(NS_GET_TIMEP(time),packet_num,packet_len);
	
  	 printf("losepacket=%lld\n",losepacket);
	speed1(NS_GET_TIMEP(time),packet_num,packet_len);
	speed2(NS_GET_TIMEP(time),packet_num,packet_len,100000,0);
 
	
	
#else
	int fd=open(filename,O_RDONLY);
	if(fd<=0)
		perror("open error\n");

	//unsigned char buf
	struct pcap_pkthdr head;
	u_char buf[3000];
	int headlen=sizeof(struct pcap_file_header);
	int phead=sizeof(struct pcap_pkthdr);
	//while(read(fd,&head,sizeof()))
	 NS_TIME_START(time); 
	printf("EIinit hb\n");
	hb=init_HB(HB_MAX);
	init_free_link(FREE_NODE);
	init_BC();//the cache for the pro classificationd
	printf("EIinit bc\n");
	init_patterns();
	//msg("EISpppppppppp");

	while(1)
	{
		lseek(fd,headlen,SEEK_SET);
		//read(fd,buf,headlen);
		while(read(fd,&head,phead))
		{
		//printf("lllll\n");
			read(fd,buf,head.caplen);
			my_callback(NULL,&head,buf);
			//printf("%d\n",head.caplen);
		}
		
	}
#endif
	


pthread_join(my_thread, NULL);
	
/////////////////////////////////////////////////////
      
        return 0;
}

#endif

