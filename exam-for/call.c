#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* 如果没有pcap的系统，要自己下载一个 */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include"deltans.h"
#include <signal.h>


#include <linux/icmp.h>
#include <net/ethernet.h>//ether_header mac头
#include <netinet/ip.h>//ip头 
#include <netinet/tcp.h>//ip头 

#include <sys/un.h>
#include"errno.h"
#include"loopbuf.h"
#define  snortnum 1
#define SEND_NUM 2
#define ALARM_SLEEP 1
/* just print a count every time we have a packet...                        */
//int exitflag=0;
//char *shmpath[20]={"/home/zhao","/lib","/libs",""};
char shmpath[20]="/home";
int flag=0;
int firstlen;
NS_TIME(time);
int n=0;
int b=0;
float f[60][10]={0.0};
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
////////////////////////

 struct ether_header *mac=NULL;
    struct ip* ip=NULL;
    struct fniff_tcp * tcp;
    struct icmphdr* icmp;
    struct udphdr* udp;
//////////////////////////
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
printf("$$$$$$$$$$$$$$$\n");
for(i=0;i<snortnum;++i)
	{printf("\nlosep[%d]=%lld\n",i,losep[i]);
	sum+=losep[i];
	printf("%d,%d\n",shmp[i]->tail,shmp[i]->head);
	}
	printf("sum=%lld\n",sum);
	//printf("%d,%d\n",shmp->tail,shmp->head);
exitflag=1;


		
  //pcap_breakloop();
}
 unsigned char tmp_buf[2048];

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    static   int count = 0;
	static int nn=0;
	static int i;

//int semnum;
		//sem_getvalue(&shmp[i]->sem,&semnum);
		//printf("sem:%d\n",semnum);
	if(exitflag)
		{
			for(i=0;i<snortnum;++i)
			{
				memcpy(shmp[i]->data[shmp[i]->tail],"########",strlen("########"));
				shmp[i]->tail=(shmp[i]->tail+1)%shmp[i]->looplen;
				my_lock_release(shmp[i]);
			}
		
				sleep(4);

			for(i=0;i<snortnum;++i)
			{
				destroy_loop(shmp[i]);
					DeleteShm(shmid[i]);
			}
		printf("count=%d\n",count);
			long long sum=0;
			for(i=0;i<snortnum;++i)
				{//printf("\nlosep[%d]=%lld\n",i,losep[i]);
				sum+=losep[i];
				//printf("%d,%d\n",shmp[i]->tail,shmp[i]->head);
				}
		printf("sum=%lld\n",sum);
		//}
			printf("exit\n");
			exit(0);
		}

    //fprintf(stdout,"%d,%d,%d\n ",pkthdr->caplen,pkthdr->len,count);
  //  fflush(stdout);
 	if(!flag&&(packet[46]=='*'))
               	{
			signal(SIGALRM, my_sigalarm);
			alarm(ALARM_SLEEP);
               		firstlen=pkthdr->caplen;
               		flag=1;
               		NS_TIME_START(time);
               	}
//if(packet[42]=='$'&&packet[43]=='$')
	

	if(packet[42]=='#'&&packet[43]=='#')
	{
		b++;
		//count--;
		//printf("end\n");
		if(b==SEND_NUM)
		{
		 NS_TIME_END(time);
          	
        	printf("firstlen:%d,recv:%d\n",firstlen,count);
		printf("count:%d\n",count);
		sleep(4);
		//break;
		int i=0;
		for(i=0;i<alarmnum;++i)
		printf("user:%.1f%%,sys:%.1f%%\n",f[i][0],f[i][2]); 
		
		for(i=0;i<snortnum;++i)
			{
				destroy_loop(shmp[i]);
					DeleteShm(shmid[i]);
			}
long long sum=0;
			for(i=0;i<snortnum;++i)
				{//printf("\nlosep[%d]=%lld\n",i,losep[i]);
				sum+=losep[i];
				//printf("%d,%d\n",shmp[i]->tail,shmp[i]->head);
				}
		printf("sum=%lld\n",sum);
		speed(NS_GET_TIMEP(time),count+sum,firstlen);
		
		exit(1);
		}
								
									
	}
	//if(packet[42]=='$'&&packet[43]=='$')
	if(1)
	{
 mac=(struct ether_header*)packet;
 if(ntohs(mac->ether_type)!=0x0800)//不是ip数据报
 	{
 	//	printf("%04x\n",ntohs(mac->ether_type));
  //     	return;
      }
   //   printf("%04x\n",ntohs(mac->ether_type));
 //ip=(struct ip*)(packet+size_mac);
//char ipdotdecs[20]={0};
 //       char ipdotdecc[20]={0};
//inet_ntop(AF_INET,(void*)&(ip->ip_src),ipdotdecs,16);
   //      inet_ntop(AF_INET,(void*)&(ip->ip_dst),ipdotdecc,16);
//printf("%s-->%s: len:%d\n",ipdotdecc,ipdotdecs,pkthdr->caplen);
		
				//sockaddlen = strlen(addr.sun_path)+sizeof(addr.sun_family);
				//nn=socket_send(sockfd,packet,pkthdr->len,0,(struct sockaddr*)&addr,sockaddlen);
		if(snortnum==1)
			i=0;
		else
			i=count%snortnum;
		/*if((shmp[i]->tail+1)%shmp[i]->looplen==shmp[i]->head)
		{
			losep[i]++;
			memcpy(shmp[0]->data[shmp[0]->tail],packet,pkthdr->len);
			//shmp[i]->tail=(shmp[i]->tail+1)%shmp[i]->looplen;
			//my_lock_release(shmp[i]);
			//return ;
			//
		}*/
		memcpy(shmp[i]->data[shmp[i]->tail],packet,pkthdr->len);
		shmp[i]->recvlen[shmp[i]->tail]=pkthdr->len;
		shmp[i]->tail=(shmp[i]->tail+1)%shmp[i]->looplen;
		
			//my_lock_release(shmp[i]);
		//printf("head=%d,tail=%d\n",shmp[i]->head,shmp[i]->tail);
		count++;
		
	}
   
}
/*void threadpro(void)
{
	printf("%%%%%%%%%%%%%%%%%%%%%%\n");
//sleep(1);
	sockfd=unix_init(&addr,&addrc,NULL);
	sockfd1=unix_init(&add2,&addrc,"/tmp/unixs1");
printf("====================\n");
	if(sockfd<=0)
		{
			perror("sock creat error\n");
			//exit(1);
			}
			printf("sockfd=%d\n",sockfd);
}*/
int main(int argc, char **argv)
{
  char *dev; /* name of the device to use */ 
  char *net; /* dot notation of the network address */
  char *mask;/* dot notation of the network mask    */
  int ret;   /* return code */
 const u_char *packet;
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
  
  printf("MASK: %s\n%d\n",mask,BUFSIZ);
 //descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
descr = pcap_open_live(dev,65536,1,0,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

//printf("pcap:%d\n",descr->bufsize);

get_sys_info(f[0],10);
usleep(600000);

 size_mac=sizeof(struct ether_header);
///////////////////////////////////

signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

//perror("what's wrong\n");
//init_loop(&shmp,&shmid,shmpath);
//init_loop(&shmp,&shmid,shmpath1);
int i;
char buf[256];
for(i=0;i<snortnum;++i)
{
losep[i]=0LL;
	sprintf(buf,"%s",shmpath);
	//puts(buf);
	init_loop(&shmp[i],&shmid[i],buf,i);
}

alarm(ALARM_SLEEP);
pcap_loop(descr,-1,my_callback,NULL);
/////////////////////////////////////
//pthread_join(threadid,NULL);
 
printf("aaaaaaa\n");
  return 0;
}
