 #define _GNU_SOURCE
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
#include <net/ethernet.h>//ether_header macÍ·
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
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sched.h>
//#include"shm/loopbuf.h"
//#include"shm/shm.h"
#include"ac/acsmx.h"
#include"mytop/top.h"

#define ALARM_SLEEP 1
extern  int get_sys_info(float *sysinfo,int n);

static char pro_map[PRO_MAX+2][20]={"HTTP","FTP","POP3","SMTP","UNKOWN","UDP","ICMP"};
static long long pronum[PRO_MAX+2]={0LL};
struct classify{
		HB * hb;
		SN * sn;
		BC * bc;
		ACSM_STRUCT * acsm;
		pthread_mutex_t work_mutex;
		//buf head and tail
		BC* head;
		BC* tail;
	};

#define CLASSIFY_NUM 1
//bind thread at core
int g_thread_at_core=0;
//core num
int g_cpu_core=1;
struct classify classifiers[CLASSIFY_NUM]; 	
int flag=0;
int firstlen;
NS_TIME(time);
int n=0;
int b=0;
float f[60][10];
int alarmnum=0;



//char *shmpath[snortnum];
int exitflag=0;
int size_mac;
int size_ip;

pcap_dumper_t *out_pcap;
///////////acsmx//////////////

long long  packet_num=0;
long long packet_len=0;


int nocase = 0;

long long find_pro=0LL;
//////////////////////////
////////////////////////

 struct ether_header *mac=NULL;
    struct ip* ip=NULL;
    struct fniff_tcp * tcp;
    struct icmphdr* icmp;
    struct udphdr* udp;
	



void my_sigalarm(int sig) {
 
	get_sys_info(f[alarmnum],10);
	alarmnum++;

  	alarm(ALARM_SLEEP);
  	signal(SIGALRM, my_sigalarm);
}
pcap_t* descr;      /*you can man it*/
void sigproc(int sig) {
	int i;
	pcap_breakloop(descr);


	//exitflag=1;
	/*for(i=0;i<PRO_MAX+2;++i)
	{

		printf("%s:%lld\n",pro_map[i],pronum[i]);
	}
	printf("\n");		
  	//pcap_breakloop();*/
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

char fortest[3000];
#define DELAY_NS 4000


void threadpro(void* _id)
{
	long thread_id = (long)_id;
	//unsigned int numCPU = sysconf( _SC_NPROCESSORS_ONLN);
	//unsigned long core_id = thread_id % numCPU;

	/**
	if computer have more cpu core, we bind thread to one core.
	*/
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET((g_thread_at_core++%g_cpu_core), &mask);
	if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) 
	{
        fprintf(stderr, "set thread affinity failed\n");
    }
    int exitflag=0;
    while(!exitflag)
    {

    }

	

	
}

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	packet_num++;
	packet_len+=pkthdr->caplen;

    static int count = 0;
	//static int nn=0;
	static int i;
	static unsigned short eth_type;
	static int vlan_flag=0;		
	static int semnum;	

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
	if((eth_type!=0x0800))//²»ÊÇipÊý¾Ý±¨
	    return;
	if(vlan_flag)
	 	ip=(struct ip*)(packet+size_mac+4);
 	else
		ip=(struct ip*)(packet+size_mac);

		
	/*char ipdotdecs[20]={0};
    char ipdotdecc[20]={0};
	inet_ntop(AF_INET,(void*)&(ip->ip_src),ipdotdecs,16);
	inet_ntop(AF_INET,(void*)&(ip->ip_dst),ipdotdecc,16);
	printf("%s-->%s: len:%d\n",ipdotdecs,ipdotdecc,pkthdr->caplen);
	*/
		
	if((ip->ip_p==6))//tcp
	{
		//msg("EIStcp\n");
		//tcp=(struct fniff_tcp*)(packet+size_mac+size_ip);
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
		hash=hash_HB(sd.b_ip,sd.l_ip);

		//hb[hash].virtual_sn_num++;
		//return ;
		classifiers[0].hb[hash].all++;
		tcplen=ntohs(ip->ip_len)-(ip->ip_hl*4)-(tcp->th_off*4);

		//msg("EIStcp11111111111\n");
		//printf("ntohs(ip->ip_len)=%d\n",ntohs(ip->ip_len)+14);
		// packet.tcp_URG=tcp->th_flags&TH_URG;
		ack=tcp->th_flags&TH_ACK;
		// packet.tcp_PSH=tcp->th_flags&TH_PUSH;
		rst=tcp->th_flags&TH_RST;
		syn=tcp->th_flags&TH_SYN;
		fin=tcp->th_flags&TH_FIN;
		datalen=pkthdr->caplen;
	   
		ptcp=(unsigned char*)tcp+(tcp->th_off*4);     	
		//msg("find\n");
		temp=find_node(classifiers[0].hb[hash].virtual_sn,&sd);  
		//msg("find end\n");
	  	//msg("ppppppppp\n");
		if(temp==NULL&&syn&&!ack&&tcplen==0)
      	{
      		//msg("E no\n");
      		//msg("get node\n");
      		SN* q=get_node(&classifiers[0].sn);
      		//msg("get node end\n");
      		q->sdipport=sd;
      		q->state=1;
			insert_node(&(classifiers[0].hb[hash].virtual_sn),q);
			classifiers[0].hb[hash].virtual_sn_num++;
			
			//msg("*****oooo*****=%ld\n",classifiers[0].hb[hash].virtual_sn_num);
		}
      	else if(temp!=NULL)
      	{
      		// printf("state:%d\n",temp->state);
      	
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
				//msg("nnnnnnnnnn,%d\n",temp->state);		      			
				//if(tcplen==0)
      			//	return;
      			//msg("W:my hash:%u\n",hash);
      			//msg("+++++\n");
				//msg("ttttttttttttt\n");
	      		p=get_BC_node(&classifiers[0].bc);
				//msg("mmmmmmmmm\n");
				if(p==NULL)
					{msg("EISget bc node error\n");exit(0);}
	      			
      			p->datalen=pkthdr->caplen;
      			p->tcplen=tcplen;
				//msg("tcplen=%d,pkthdr->caplen=%d\n",tcplen,pkthdr->caplen);
				if(tcplen<0)
				{
					msg("EIS tcp<0\n");
					exit(0);
				}				
      			p->next=NULL;
      			memcpy(p->buf,packet,pkthdr->caplen);
				p->ptcp=(unsigned char*)(p->buf)+(tcp->th_off*4)+((unsigned char*)tcp-(unsigned char*)mac);//ptcp;
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
      			if((temp->state==9)||rst||fin||(temp->tcp_content_len>150))
      			{
      				//msg("EIS static\n");
					#if 0
	      				p=temp->bc_head;
	      				while(p!=NULL)
	      				{				
						if(p->tcplen!=0)
						acsmSearch(acsm,p->ptcp,p->tcplen,PrintMatch);
	      					p=p->next;
	      				}
					#else
					//acSearch(acsm,temp->bc_head);
					
	      				acSearch(classifiers[0].acsm,temp->bc_head);
					#endif
	      				i=getSummary(classifiers[0].acsm->acsmPatterns,feature_num); 
					    		
					//show the result of pro
					msg("i=%d=%s\n",i,pro_map[i]);
	      				pronum[i]++;
					temp->proto=i;
      				if(rst||fin)
      				{
      					//msg("rst fin\n");
						temp->state=10;
						resume_BC_node(&classifiers[0].bc,temp->bc_head);
						temp->bc_head=NULL;
						temp->bc_tail=NULL;

						//printf("1111111111\n");
						remove_HB_SN(&(classifiers[0].hb[hash].virtual_sn),temp);
      					resume_node(&classifiers[0].sn,temp);
      					classifiers[0].hb[hash].virtual_sn_num--;
      					
						//msg("*tt********=%ld\n",hb[hash].virtual_sn_num);
						if(classifiers[0].hb[hash].virtual_sn_num==0)
							classifiers[0].hb[hash].virtual_sn=NULL;
      					return;
      				}
      				temp->state=10;
      				//msg("resume_node\n");
      				resume_BC_node(&classifiers[0].bc,temp->bc_head);
      				//msg("resume_node_end\n");
	      			temp->bc_head=NULL;
	      			temp->bc_tail=NULL;
      			}
      			
      		}
      		else if(temp->state>=10)
      		{	
				//msg("Ehhhhh:%d\n",pkthdr->caplen);
				if(pkthdr->caplen<MAX_BUFFER_FOR_PACKET)
					memcpy(fortest,packet,pkthdr->caplen);

	      		if(rst||fin)
				{
					//msg("fin  rst %d\n",__LINE__);
					//printf("2222222222222,%d,%d\n",hb[hash].virtual_sn_num,temp->state);
					remove_HB_SN(&(classifiers[0].hb[hash].virtual_sn),temp);
					//msg("fin %d\n",__LINE__);
					resume_node(&classifiers[0].sn,temp);
					//msg("resume end\n",__LINE__);
					classifiers[0].hb[hash].virtual_sn_num--;
					//msg("**************=%ld\n",hb[hash].virtual_sn_num);
					if(classifiers[0].hb[hash].virtual_sn_num==0)
						classifiers[0].hb[hash].virtual_sn=NULL;
					return;
				}
      		} 
			else
			{
				//msg("ggggggggggg\n");
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
		hash=hash_HB(sd.b_ip,sd.l_ip);
		//fprintf(stdout,"2B udp src port:%d\t",ntohs(udp->source));
		//fprintf(stdout,"2B udp dst port:%d\n",ntohs(udp->dest));
	}   
	else
	{
		//printf("no\n");
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
		
		//exitflag=0;
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

int main(int argc, char **argv)
{
	char *dev; /* name of the device to use */ 
	char *net; /* dot notation of the network address */
	char *mask;/* dot notation of the network mask    */
	int ret;   /* return code */
	//const u_char *packet;
	//pcap_t* descr;      /*you can man it*/
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

	//descr = pcap_open_live(dev,65536,1 ,0,errbuf);
	descr = pcap_open_live(dev,MAX_BUFFER_FOR_PACKET,1 ,0,errbuf);
	// descr = pcap_open_live(NULL,BUFSIZ,1 ,0,errbuf);
	if(descr == NULL)
	{ printf("pcap_open_live(): %s\n",errbuf); exit(1); }

	//printf("pcap:%d\n",descr->bufsize);

	get_sys_info(f[0],10);
	usleep(600000);
	
	

	size_mac=sizeof(struct ether_header);
	size_ip=sizeof(struct ip);
	///////////////////////////////////

	signal(SIGINT, sigproc);
	signal(SIGTERM, sigproc);
	signal(SIGINT, sigproc);

	//////////////
	//compile ac dfa
	///////////////

	
	int ncalss;
	pthread_t ids[CLASSIFY_NUM];
	for(ncalss=0; ncalss<CLASSIFY_NUM; ++ncalss)
	{

		if (init_HB(&classifiers[ncalss].hb) < 0)
		{
			printf("init hb error\n");
		}
		/**
		init free node 
		***/
		
		init_free_link(&classifiers[ncalss].sn, FREE_NODE);
		init_BC(&classifiers[ncalss].bc);//the cache for the pro classificationd
		init_patterns(&classifiers[ncalss].acsm);
		pthread_mutex_init(&classifiers[ncalss].work_mutex,NULL);
		classifiers[ncalss].head=NULL;
		classifiers[ncalss].tail=NULL;
		//create thread
		int ret;
		ret=pthread_create(&ids[ncalss],NULL,(void *) threadpro,(void*)ncalss);
		if(ret!=0){ 
			printf ("Create pthread error!\n"); 
			exit (1); 
		} 
		//msg("EISpppppppppp");

	}
	

	cpu_set_t cpumask;
	CPU_ZERO(&cpumask);
	CPU_SET((g_thread_at_core++%g_cpu_core), &cpumask);

	g_cpu_core = sysconf(_SC_NPROCESSORS_CONF);



	if (sched_setaffinity(0, sizeof(cpumask), &cpumask) == -1)
	{
		printf("warning: could not set CPU affinity, continuing...\n");
	}

	pcap_loop(descr,-1,my_callback,NULL);


	/////////////////////////////////////
	//pthread_join(threadid,NULL);
	int i;
	for(i=0;i<PRO_MAX+2;++i)
	{

		printf("%s:%lld\n",pro_map[i],pronum[i]);
  	}
   	printf("losepacket=%lld\n",losepacket);
	//sem_post(&bin_sem);
	NS_TIME_END(time);

	speed1(NS_GET_TIMEP(time),packet_num,packet_len);

	
	for(ncalss=0; ncalss<CLASSIFY_NUM; ++ncalss)
	{			
		pthread_join(ids[ncalss],NULL);

	}
	
	for(ncalss=0; ncalss<CLASSIFY_NUM; ++ncalss)
	{
		//del_HB(&hb);		
		del_HB(&classifiers[ncalss].hb, &classifiers[ncalss].sn);
		//acsmFree (acsm);		
		acsmFree (classifiers[ncalss].acsm);
	}
	msg("exit\n");
	return 0;
}


