#include <stdio.h>
#include"unistd.h"
#include <stdlib.h>
#include <pcap.h>  /* 如果没有pcap的系统，要自己下载一个 */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include"deltans.h"
#include <signal.h>

#include"fcntl.h"
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include"load.h"
#include <linux/icmp.h>
#include <net/ethernet.h>//ether_header mac头
#include <netinet/ip.h>//ip头 
#include <netinet/tcp.h>//ip头 
#include"linux/if_ether.h"

#include <sys/un.h>
#include"errno.h"
#include"shm/loopbuf.h"
#include"shm/shm.h"
#include"ac/acsmx.h"
#include"mytop/top.h"

#include <net/if.h>
#include<netinet/udp.h>
#include <netdb.h>
	#include"fcntl.h"
#include <net/ethernet.h>//ether_header mac头


#include"time.h"

#define  snortnum 1
#define SEND_NUM 1
#define ALARM_SLEEP 1
extern  int get_sys_info(float *sysinfo,int n);
/* just print a count every time we have a packet...                        */
//int exitflag=0;
//char *shmpath[20]={"/home/zhao","/lib","/libs",""};
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
 typedef u_int32_t tcp_seq;
struct fniff_tcp
  {
    u_int16_t th_sport;		/* source port */
    u_int16_t th_dport;		/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;		/* (unused) */
    u_int8_t th_off:4;		/* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;		/* data offset */
    u_int8_t th_x2:4;		/* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
};

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


///////////acsmx//////////////
extern ACSM_STRUCT * acsm;

HB* hb;
//static char pro_patern[120][256]={
//{"http"},{"put"},{"get"}
//};  
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


void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    static   int count = 0;
	//static int nn=0;
	static int i;
static BC *p;

//int semnum;
		//sem_getvalue(&shmp[i]->sem,&semnum);
		//printf("sem:%d\n",semnum);
	//	printf("ccccccccc\n");
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
		printf("count=%d,\nfind_pro=%lld\n",count,find_pro);
		//}
			printf("exit\n");
			exit(0);
		}

   // fprintf(stdout,"%d,%d,%d\n ",pkthdr->caplen,pkthdr->len,count);
  //  fflush(stdout);
 /*	if(!flag&&(packet[46]=='*'))
               	{
			signal(SIGALRM, my_sigalarm);
			alarm(ALARM_SLEEP);
               		firstlen=pkthdr->caplen;
               		flag=1;
               		NS_TIME_START(time);
               	}*/
//if(packet[42]=='$'&&packet[43]=='$')
	

	/*if(packet[42]=='#'&&packet[43]=='#')
	{
		b++;
		//count--;
		//printf("end\n");
		if(b==SEND_NUM)
		{
		 NS_TIME_END(time);
          	speed(NS_GET_TIMEP(time),count,firstlen);
        	printf("firstlen:%d,recv:%d\n",firstlen,count);
		//break;
		int i=0;
		for(i=0;i<alarmnum;++i)
		printf("user:%.1f%%,sys:%.1f%%\n",f[i][0],f[i][2]); 
		exit(1);
		}
								
									
	}*/
	//if(packet[42]=='$'&&packet[43]=='$')

 mac=(struct ether_header*)packet;
 if(ntohs(mac->ether_type)!=0x0800)//不是ip数据报
       	return;
 ip=(struct ip*)(packet+size_mac);
 
char ipdotdecs[20]={0};
       char ipdotdecc[20]={0};
inet_ntop(AF_INET,(void*)&(ip->ip_src),ipdotdecs,16);
        inet_ntop(AF_INET,(void*)&(ip->ip_dst),ipdotdecc,16);
printf("\n%s-->%s: len:%d\n",ipdotdecs,ipdotdecc,pkthdr->caplen);
//return;	
				//sockaddlen = strlen(addr.sun_path)+sizeof(addr.sun_family);
				//nn=socket_send(sockfd,packet,pkthdr->len,0,(struct sockaddr*)&addr,sockaddlen);
				
			
		if((ip->ip_p==6))//tcp
		{
				//msg("EIStcp\n");
				tcp=(struct fniff_tcp*)(packet+size_mac+size_ip);
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
//msg("");
			//	printf("ntohs(ip->ip_len)=%d\n",ntohs(ip->ip_len)+14);
				// packet.tcp_URG=tcp->th_flags&TH_URG;
        			  ack=tcp->th_flags&TH_ACK;
        			 // packet.tcp_PSH=tcp->th_flags&TH_PUSH;
        			  rst=tcp->th_flags&TH_RST;
        			  syn=tcp->th_flags&TH_SYN;
        			  fin=tcp->th_flags&TH_FIN;
         datalen=pkthdr->caplen;
        //int tcplen=ntohs(ip->ip_len)-ip->ip_hl<<2-(tcp->th_off)<<2;
         ptcp=(unsigned char*)tcp+(tcp->th_off*4);
       // msg("EISfind--,%u\n",hash);
        temp=find_node(hb[hash].virtual_sn,&sd);
       // 	msg("EISppppppppppp\n");
       printf("tcp=%d,ack=%d,syn=%d,fin=%d\n",tcplen,ack?1:0,syn?1:0,fin?1:0);
      // 	return ;
      
        if(temp==NULL&&syn&&!ack&&tcplen==0)//not find
      	{
      		//msg("E no\n");
      		SN* q=get_node();
      		q->sdipport=sd;
      		q->state=1;
      			insert_node(&(hb[hash].virtual_sn),q);
      			hb[hash].virtual_sn_num++;
      	}
      	else if(temp!=NULL)
      	{
      		 //printf("state:%d\n",temp->state);
      	
      		if((temp->state==1)&&syn&&ack&&(tcplen==0))
      		{
      			//msg("W:my ooooooooooooooooooo\n");
      			temp->state=2;
      		}
      		else if(temp->state==2&&ack&&!syn&&tcplen==0)
      		{
      			temp->state=3;
      			//msg("W:its ===============================static\n");
      				//msg("W:my hash:%u\n",hash);
      		}
      		else if(temp->state>=3&&temp->state<9)
      		{
      			if(tcplen==0)
      				return;
      					//msg("W:my hash:%u\n",hash);
      			//msg("+++++\n");
      			p=get_BC_node();
						if(p==NULL)
							msg("EISget bc node error\n");
      			p->ptcp=ptcp;
      			p->datalen=pkthdr->caplen;
      			p->tcplen=tcplen;
					if(tcplen<0)
						{
						msg("EIS tcp<0\n");
						exit(0);
						}
						//msg("EISvirtual_sn_num=%d\n",hb[hash].virtual_sn_num);
      			//msg("tcplen=%d\n",tcplen);
      			p->next=NULL;
      			memcpy(p->buf,packet,pkthdr->caplen);
      			temp->tcp_content_len+=tcplen;
      			if(temp->bc_head==NULL)
      			{
      				temp->bc_head=temp->bc_tail=p;
      			}
      			else
      			{
      				temp->bc_tail->next=p;
      				temp->bc_tail=p;
      			}
      			temp->state++;
      			if((temp->state==9)||rst||fin||(temp->tcp_content_len>100))
      			{
      				//msg("EIS static\n");
      				p=temp->bc_head;
      				while(p!=NULL)
      				{

						//if(p->tcplen<0)
      						//{msg("EIS start,p->tcplen=%d\n",p->tcplen);exit(0);}
      						msg("%s\n",p->ptcp);
      						if(p->tcplen!=0)
      					acsmSearch(acsm,p->ptcp,p->tcplen,PrintMatch);
      					msg("======%d,%s\n",p->tcplen,p->ptcp);
      						//msg("EIS end\n");
					//msg("tcplen:%d\n",p->tcplen);
      					p=p->next;
      				}
      				printf("mmmmmmm----%d&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n",getSummary(acsm->acsmPatterns,feature_num));
//exit(0);
      				if(rst||fin)
      				{
      					resume_node(temp);
      					hb[hash].virtual_sn_num--;
      					return;
      				}
      				temp->state=10;
      				resume_BC_node(temp->bc_head);
      			temp->bc_head=NULL;
      			temp->bc_tail=NULL;
      			}
      			
      		}
      		else if(temp->state>=10)
      		{
      			if(rst||fin)
      				{
      					resume_node(temp);
      					hb[hash].virtual_sn_num--;
      					return;
      				}
      		} 
      		
      	}     	
        	
	    
     }//tcp
/*	if(snortnum==1)
			i=0;
		else
			i=count%snortnum;
		if((shmp[i]->tail+1)%shmp[i]->looplen==shmp[i]->head)
		{
			losep[i]++;
			my_lock_release(shmp[i]);
			return ;
			//
		}
		memcpy(shmp[i]->data[shmp[i]->tail],packet,pkthdr->len);

		shmp[i]->recvlen[shmp[i]->tail]=pkthdr->len;
		shmp[i]->tail=(shmp[i]->tail+1)%shmp[i]->looplen;
		
			my_lock_release(shmp[i]);
		//printf("head=%d,tail=%d\n",shmp[i]->head,shmp[i]->tail);
		count++;
		*/

   
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
int main(int argc, char **argv)
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
#define __PCAP__
#ifdef __PCAP__
 descr = pcap_open_live(dev,BUFSIZ,1 ,0,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }
#endif
//printf("pcap:%d\n",descr->bufsize);

get_sys_info(f[0],10);
usleep(600000);

 size_mac=sizeof(struct ether_header);
 size_ip=sizeof(struct ip);
///////////////////////////////////

signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

//perror("what's wrong\n");
//init_loop(&shmp,&shmid,shmpath);
//init_loop(&shmp,&shmid,shmpath1);
int i;
char buf[256];
printf("1111111111111111\n");
for(i=0;i<snortnum;++i)//create shm
{
losep[i]=0LL;
	sprintf(buf,"%s",shmpath);
	//puts(buf);
	init_loop(&shmp[i],&shmid[i],buf,i);
}
//////////////
//compile ac dfa
///////////////
printf("EIinit hb\n");
hb=init_HB(HB_MAX);
	init_free_link(FREE_NODE);
	init_BC();//the cache for the pro classificationd
	printf("EIinit bc\n");
	init_patterns();
	//msg("EISpppppppppp");

//#define __PCAP__ 
#ifdef __PCAP__
pcap_loop(descr,-1,my_callback,NULL);
#else
//void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*        packet)
u_char packet[65535];
struct pcap_pkthdr pkthdr;
int sockfd;
if ((sockfd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IP))) < 0)
   {
       printf ("create socket failed\n");
       return -1;
   }

   if (0 != set_promisc ("eth0", sockfd))
   {
       printf ("Failed to set interface promisc mode\n");
   }
while(1)
{
	memset(packet,0,65535);
	pkthdr.caplen = recvfrom (sockfd, packet, 2048, 0, NULL, NULL);	
	my_callback(NULL,&pkthdr,packet);
	
}
#endif
/////////////////////////////////////
//pthread_join(threadid,NULL);
 
printf("aaaaaaa\n");
  return 0;
}
