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
#include "fcntl.h"
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>

#include <linux/icmp.h>
#include <net/ethernet.h>//ether_header macÍ·
#include <netinet/ip.h>//ipÍ· 
#include <netinet/tcp.h>//ipÍ· 
#include <net/ethernet.h>//ether_header macÍ·
#include "linux/if_ether.h"
#include <sys/un.h>
#include "errno.h"

#include <net/if.h>
#include <netinet/udp.h>
#include <netdb.h>
#include "deltans.h"
#include "load.h"
#include "time.h"
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sched.h>
//#include"shm/loopbuf.h"
//#include"shm/shm.h"
#include"ac/acsmx.h"
#include"mytop/top.h"

#define SERVPORT 3333 
#define BACKLOG 10 

#define ALARM_SLEEP 1

#define SEND_TO_CLIENT 1

extern  int get_sys_info(float *sysinfo,int n);

static char pro_map[PRO_MAX+2][20]={"HTTP","FTP","POP3","SMTP","UNKOWN","UDP","ICMP"};
static long long pronum[PRO_MAX+2]={0LL};
struct classify{
		HB * hb;
		SN * sn;
		BC * bc;
		ACSM_STRUCT * acsm;
		pthread_mutex_t work_mutex;// for the bc head an tail
		//buf head and tail
		BC* head;
		BC* tail;
		pthread_mutex_t BC_mutex;

	};

pthread_mutex_t thread_mutex;
//must the 2's pow
#define CLASSIFY_NUM 1


typedef struct _loadNode{
	
	int probe_id;
	int load_value;
	int clientfd;
}LN;

LN load_table[40];


//bind thread at core
int g_thread_at_core=0;
unsigned short g_thread_mask=0;
//core num
int g_cpu_core=1;
struct classify classifiers[CLASSIFY_NUM]; 	//number of the classify
int efd[CLASSIFY_NUM]={0};//number of the 
int maxnum[CLASSIFY_NUM]={0};

int g_getPacketStartFlag=0;
long g_sendpacket = 0L;

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
void my_sigalarm(int sig) {
 
	get_sys_info(f[alarmnum],10);
	alarmnum++;

  	alarm(ALARM_SLEEP);
  	signal(SIGALRM, my_sigalarm);
}
pcap_t* descr;      /*you can man it*/
void sigproc(int sig) {
	msg("ESI[[[[[[[[[[[[[[[[[[[[[[[[[sig=%d\n",sig);
	if (SIGPIPE != sig)
	{
		msg ("ESI exitflag=1\n");
		exitflag=1;

	} else {
		msg("ESI }}}}}}}}}}}}}}}}}}}the sig is sigpipe\n");
		g_getPacketStartFlag = 0;
		close(load_table[0].clientfd);
	}
	//sleep(2);
	pcap_breakloop(descr);


	
	msg("sigproc exit\n");
	
}


//static BC *p;
long long losepacket=0;

char fortest[3000];
#define DELAY_NS 4000


int full_send(int sockfd, char * buf, int buflen, int flag)
{
	if (buflen > MAX_BUFFER_FOR_PACKET)
		{
			msg("ESI =%d\n",buflen);
			return -1;
		}
	if (sockfd <= 0)
		return -1;
	if (MAX_BUFFER_FOR_PACKET < buflen)
		buflen = MAX_BUFFER_FOR_PACKET;
	int havesend = send(sockfd, buf, buflen, flag);
	if (havesend == buflen) {
			
			return 0;
		}
	if (havesend < buflen) {
		if (havesend == -1 && errno != EAGAIN){
			msg("ESIhavesend=%d\n",havesend);
			return -1;
		}
		if (havesend == 0) {
			msg("ESI havesend=0\n");
			return -1;
		}

		fd_set writefds;//
		struct timeval tv;
		int sendlen;
		
		while(1)
		{
			FD_ZERO(&writefds);
			FD_SET(sockfd,&writefds);
			
			tv.tv_sec = 2;
			tv.tv_usec = 0;
			int ret=select(sockfd+1, NULL, &writefds, NULL, &tv);
			if(exitflag)
	    	{
	    		msg("exit\n");
	    		return -1;
	    	}
			if(ret<0){
				if (errno != EAGAIN){
					msg("WSIsomethine is wrong\n");
					return -1;
				}
				msg("ESIret=%d\n",ret);
				continue;
			}
			else if (ret==0) 
			{
				msg("WIStime out... buflen=%d\n",buflen);
				sleep(1);
				continue;
			}
			else
			{			
				if (FD_ISSET(sockfd, &writefds))
				{			
					sendlen = send(sockfd, buf, buflen - havesend, flag);				
					if (sendlen == -1 ){
						if (errno != EAGAIN && errno != EINTR)
						{
							msg("ESIsendlen=-1\n");
							return -1;
						}
						msg("WSI sendlen \n");
						continue;
					}
					else if (sendlen == 0)
					{
						msg("WSI sendlen =0\n");
						return -1;
					}

					else //(sendlen !=-1)
					{
						havesend += sendlen;
						if (havesend == buflen){
							
							return 0;
						}
						
							
					}
						
				}
				else
				{
					msg("ESI***********\n");
				}
				
			}

			
		}


	}


}
void threadpro(void* _id)
{
	long thread_id = (long)_id;
	//unsigned int numCPU = sysconf( _SC_NPROCESSORS_ONLN);
	//unsigned long core_id = thread_id % numCPU;
	 uint64_t  count=0L;
	  struct ether_header *mac=NULL;
     struct ip* ip=NULL;
     struct fniff_tcp * tcp;
    //static struct icmphdr* icmp;
     struct udphdr* udp;
    BC* p;
    int resumeBCNodeFlag=0;
	
	SSDD sd;
	int tcplen;
	int fin;
	int ack;
	int syn;
	int rst;
	unsigned short hash;
	SN* temp;

	int datalen;

	/**
	if computer have more cpu core, we bind thread to one core.
	*/
	cpu_set_t mask;
	CPU_ZERO(&mask);
	
	pthread_mutex_lock(&thread_mutex);
	CPU_SET((g_thread_at_core++%g_cpu_core), &mask);
	
	if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) 
	{
        fprintf(stderr, "set thread affinity failed\n");
    } 

    msg("thread %d start, bind to %d \n", thread_id,(g_thread_at_core-1)%g_cpu_core);
    pthread_mutex_unlock(&thread_mutex);
    int ret = 0;       
    int ep_fd = -1;
    struct epoll_event events[10];
    if (efd[thread_id] < 0)
    {
        printf("efd not inited.\n");
        goto fail;
    }
    ep_fd = epoll_create(1024);
    if (ep_fd < 0)
    {
        perror("epoll_create fail: ");
        goto fail;
    }

    struct epoll_event read_event;

    read_event.events = EPOLLHUP | EPOLLERR | EPOLLIN;//EPOLLET;
    read_event.data.fd = efd[thread_id];

    ret = epoll_ctl(ep_fd, EPOLL_CTL_ADD, efd[thread_id], &read_event);
    if (ret < 0)
    {
        perror("epoll ctl failed:");
        goto fail;
    } 
    int i = 0;     
    int counti;
    int proi;
    int bcnum;
    unsigned int headlen;
    while (!exitflag)
    {
       
        ret = epoll_wait(ep_fd, &events[0], 10, 2000);  
        //msg("epoll wait ret =%d\n",ret);      
        if (ret > 0)
        {
          
            for (i=0 ; i < ret; i++)
            {
               // printf("%d\n",i);
                if (events[i].events & EPOLLHUP)
                {
                    msg("epoll eventfd has epoll hup.\n");
                   // goto fail;
                }
                else if (events[i].events & EPOLLERR)
                {
                    msg("epoll eventfd has epoll error.\n");
                    goto fail;
                }
                else if (events[i].events & EPOLLIN)
                {
                   //int event_fd = events[i].data.fd;
                    int res = read(events[i].data.fd, &count, sizeof(count));   
                    
                    //msg("thread event_fd =%d  thread_id =%d read count=%d\n",event_fd,thread_id,count);   
                    //if(count>1)
                    	//msg("count=%d\n",count); 

                    if (res < 0)
                    {
                        perror("read fail:");
                        goto fail;
                    }
                    else
                    {                   	             	
                    	if(count>4000)
                    			maxnum[thread_id]++;
                    	for(counti=0; counti<count; ++counti)
                    	//for(counti=0; counti<count; )
                    	{
                    		resumeBCNodeFlag=1;
                    		//if(count>maxnum[thread_id])
                    		//	maxnum[thread_id]=count;
                    		
                    		if (count-counti<2)
                    		pthread_mutex_lock(&classifiers[thread_id].work_mutex);
                    		
                    		
                    		p = classifiers[thread_id].head;
                    		if (p == NULL)
                    			{msg("head error count:%d counti:%d\n",count,counti);break;}
                    		
                    		if (classifiers[thread_id].tail == classifiers[thread_id].head)// if queue is the end
                    		{
                    			//if (classifiers[thread_id].head->next!=NULL)
                    			//	msg("queue next error\n");
                    			classifiers[thread_id].tail = NULL;
                    			classifiers[thread_id].head = NULL;

                    		}
                    		else// not the end
                    		{
                    			classifiers[thread_id].head = classifiers[thread_id].head->next;
                    			///if (classifiers[thread_id].head==NULL)
                    			//	msg("queue error\n");
                    		}                    		
						
							if(count-counti<2)
								pthread_mutex_unlock(&classifiers[thread_id].work_mutex);
							p->next=NULL;	
							ip = p->ip;
							//msg("EI msg\n");
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
								//msg("hash=%u\n",hash);
								//hb[hash].virtual_sn_num++;
								//return ;
								classifiers[thread_id].hb[hash].all++;
								tcplen=ntohs(ip->ip_len)-(ip->ip_hl*4)-(tcp->th_off*4);

								//msg("EIStcp11111111111\n");
								//printf("ntohs(ip->ip_len)=%d\n",ntohs(ip->ip_len)+14);
								// packet.tcp_URG=tcp->th_flags&TH_URG;
								ack=tcp->th_flags&TH_ACK;
								// packet.tcp_PSH=tcp->th_flags&TH_PUSH;
								rst=tcp->th_flags&TH_RST;
								syn=tcp->th_flags&TH_SYN;
								fin=tcp->th_flags&TH_FIN;
								datalen=p->datalen;
							   
								//ptcp=(unsigned char*)tcp+(tcp->th_off*4);     	
								
								temp=find_node(classifiers[thread_id].hb[hash].virtual_sn,&sd);  
								
							  	//msg("ppppppppp\n");
								if(temp==NULL&&syn&&!ack&&tcplen==0)
						      	{
						      		//msg("E no\n");
						      		//msg("get node\n");
						      		SN* q=get_node(&classifiers[thread_id].sn);
						      		//msg("get node end\n");
						      		q->sdipport=sd;
						      		q->state=1;
									insert_node(&(classifiers[thread_id].hb[hash].virtual_sn),q);
									classifiers[thread_id].hb[hash].virtual_sn_num++;

									
									
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
						      			p->tcplen=tcplen;
										//msg("tcplen=%d,pkthdr->caplen=%d\n",tcplen,pkthdr->caplen);
										if(tcplen<0)
										{
											msg("EIS tcp<0\n");
											exit(0);
										}				
						      			
										//p->ptcp=(unsigned char*)(p->buf)+(tcp->th_off*4)+((unsigned char*)tcp-(unsigned char*)mac);//ptcp;
						      			p->ptcp=(unsigned char*)(tcp)+(tcp->th_off*4);//ptcp;
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
						      			resumeBCNodeFlag=0;
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
												//msg("EI AC\n");
							      				acSearch(classifiers[thread_id].acsm,temp->bc_head);
												//msg("EI ac end\n");
											#endif
							      				proi=getSummary(classifiers[thread_id].acsm->acsmPatterns,feature_num); 
											    	
											//show the result of pro
											//msg("proi=%d=%s\n",proi,pro_map[proi]);
							      				pronum[proi]++;
											temp->proto = proi;

											//chose the lower probe
											temp->id = 0;
						      				
						      				temp->state=10;
											pthread_mutex_lock(&classifiers[thread_id].BC_mutex);
											
											#ifdef SEND_TO_CLIENT
												if (load_table[temp->id].clientfd != -1)
												{
													p = temp->bc_head;
													while(p!=NULL)
													{
														headlen = 0x7E7E0000|p->datalen;
														if (g_getPacketStartFlag && (full_send(load_table[temp->id].clientfd,&headlen,4,0) < 0))
														{
																
																g_getPacketStartFlag=0;
																msg("EIS  send error,load_table[temp->id].clientfd=%d\n",load_table[temp->id].clientfd);
																close(load_table[temp->id].clientfd);
																load_table[temp->id].clientfd=-1;
																//goto fail;
														} else {
															
														} 

														if (g_getPacketStartFlag && (full_send(load_table[temp->id].clientfd,p->buf,p->datalen,0) < 0))
														{
															
															g_getPacketStartFlag=0;
															msg("EIS  send error\n");
															close(load_table[temp->id].clientfd);
																load_table[temp->id].clientfd=-1;
															//goto fail;
														}
														else
														{
															g_sendpacket++;
														}
														p=p->next;													
													}
												}
											#endif
											resume_BC_node(&classifiers[thread_id].bc,temp->bc_head);		
											

											pthread_mutex_unlock(&classifiers[thread_id].BC_mutex);
											temp->bc_head=NULL;
											temp->bc_tail=NULL;
											
											//printf("1111111111\n");
											if(rst||fin)
						      				{
												remove_HB_SN(&(classifiers[thread_id].hb[hash].virtual_sn),temp);
						      					resume_node(&classifiers[thread_id].sn,temp);
						      					classifiers[thread_id].hb[hash].virtual_sn_num--;
						      					
												//msg("*tt********=%ld\n",hb[hash].virtual_sn_num);
												if(classifiers[thread_id].hb[hash].virtual_sn_num==0)
													classifiers[thread_id].hb[hash].virtual_sn=NULL;
						      					
						      				}
						      				
											
						      				
						      				
							      			
						      			}
						      			
						      		}
						      		else if(temp->state >= 10)
						      		{	
										#ifdef SEND_TO_CLIENT
										headlen = 0x7E7E0000|p->datalen;
										if (g_getPacketStartFlag && (full_send(load_table[temp->id].clientfd,&headlen,4,0) < 0))
											{
											
												g_getPacketStartFlag = 0;
													msg("EIS  send error\n");
													//goto fail;
												} else {
													
														} 
						      			if (g_getPacketStartFlag && (full_send(load_table[temp->id].clientfd,p->buf,p->datalen,0) < 0))
											{
												g_sendpacket++;
												g_getPacketStartFlag=0;
												msg("EIS  send error\n");
												close(load_table[temp->id].clientfd);
												load_table[temp->id].clientfd=-1;
												//goto fail;
											}
											else
														{
															g_sendpacket++;
														}
										#endif
							      		if(rst||fin)
										{
											//msg("fin  rst %d\n",__LINE__);
											//printf("2222222222222,%d,%d\n",hb[hash].virtual_sn_num,temp->state);
											remove_HB_SN(&(classifiers[thread_id].hb[hash].virtual_sn),temp);
											//msg("fin %d\n",__LINE__);
											resume_node(&classifiers[thread_id].sn,temp);
											//msg("resume end\n",__LINE__);
											classifiers[thread_id].hb[hash].virtual_sn_num--;
											//msg("**************=%ld\n",hb[hash].virtual_sn_num);
											if(classifiers[thread_id].hb[hash].virtual_sn_num==0)
												classifiers[thread_id].hb[hash].virtual_sn=NULL;
											
										}
						      		} 
						      		
									/*else
									{
										//msg("ggggggggggg\n");
									}*/
						      		
						      	}     	
								
								    
						    }//tcp
						    else if(ip->ip_p==1)//icmp
						    {
						    	//msg("EISicmp\n");
								//printf("2222\n");
						     	//static char pro_map[PRO_MAX+2][20]={"HTTP","FTP","POP3","SMTP","UNKOWN","UDP","ICMP"};
						     	#ifdef SEND_TO_CLIENT
						     	headlen = 0x7E7E0000|p->datalen;
						     	if (g_getPacketStartFlag && (full_send(load_table[0].clientfd,&headlen,4,0) < 0))
									{
										
											msg("EIS  send error\n");g_getPacketStartFlag=0;
											close(load_table[0].clientfd);
											load_table[0].clientfd=-1;
										//goto fail;
									} else {
										if (g_getPacketStartFlag)
															printf("send :%d\n",p->datalen);
														} 					

						     	if (g_getPacketStartFlag &&  (full_send(load_table[0].clientfd,p->buf,p->datalen,0) < 0))
									{
										
										
										msg("EIS  send error\n");g_getPacketStartFlag=0;
										close(load_table[0].clientfd);
											load_table[0].clientfd=-1;
										//goto fail;
									}
									else
														{
															g_sendpacket++;
														}
								#endif
						 		pronum[PRO_MAX+1]++;
						    }
						    else if(ip->ip_p==17)//udp
							{
								//printf("1111111\n");
								//msg("EISudp\n");
								pronum[PRO_MAX]++;

								udp=(struct udphdr *)(p->buf+size_mac+size_ip);
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
								#ifdef SEND_TO_CLIENT
								headlen = 0x7E7E0000|p->datalen;
								if (g_getPacketStartFlag &&  (full_send(load_table[0].clientfd,&headlen,4,0) < 0))
									{
										
										msg("EIS  send error\n");g_getPacketStartFlag=0;
										close(load_table[0].clientfd);
											load_table[0].clientfd=-1;
										//goto fail;
									} else {
										
														} 

								if (g_getPacketStartFlag && (full_send(load_table[0].clientfd,p->buf,p->datalen,0) < 0))
									{
										g_sendpacket++;
								
										msg("EIS  send error\n");g_getPacketStartFlag=0;
										close(load_table[0].clientfd);
											load_table[0].clientfd=-1;
										//goto fail;
									}
									else
														{
															g_sendpacket++;
														}
								#endif
								//fprintf(stdout,"2B udp src port:%d\t",ntohs(udp->source));
								//fprintf(stdout,"2B udp dst port:%d\n",ntohs(udp->dest));
							}   
							else
							{
								#ifdef SEND_TO_CLIENT
								headlen = 0x7E7E0000|p->datalen;
								if (g_getPacketStartFlag && (full_send(load_table[0].clientfd,&headlen,4,0) < 0))
									{
									
										msg("EIS  send error\n");g_getPacketStartFlag=0;
										close(load_table[0].clientfd);
											load_table[0].clientfd=-1;
										//goto fail;
									} else {
										
														} 

								if (g_getPacketStartFlag && (full_send(load_table[0].clientfd,p->buf,p->datalen,0) < 0))
									{
										g_sendpacket++;
										msg("EIS  send error\n");g_getPacketStartFlag=0;
										close(load_table[0].clientfd);
											load_table[0].clientfd=-1;
										//goto fail;
									}
									else
														{
															g_sendpacket++;
														}
								#endif
								//msg("EISnot know\n");
								//printf("no\n");
							}
							if (resumeBCNodeFlag)
							{
								pthread_mutex_lock(&classifiers[thread_id].BC_mutex);
								resume_BC_node(&classifiers[thread_id].bc,p);
								pthread_mutex_unlock(&classifiers[thread_id].BC_mutex);
							}
							
						}//end count
                       
                    }
                }
            }
        }
        else if (ret == 0)
        {
        	if(exitflag)
        	{
        		msg("thread exit\n");
        		goto fail;
        	}
            /* time out */
           // msg("epoll wait timed out. thread_id=%d\n",thread_id);
          
        }
        else
        {
        	if(exitflag)
        	{
        		msg("thread exit\n");
        		goto fail;
        	}
            perror("epoll wait error:");
            goto fail;
        }
    }     
    fail:
    if (ep_fd >= 0)
    {
        close(ep_fd);
        ep_fd = -1;
    }       
    msg ("ESI exitflag=1\n");
    exitflag = 1 ;
    msg("thread end\n"); 
	pthread_exit(NULL);	
}

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	
	  
	//static int nn=0;
	//static int i;
	static unsigned short eth_type;
	static int vlan_flag=0;
	static unsigned int sip,dip;	
	static unsigned short classid;
	static uint64_t count=1L;
	static struct ether_header *mac=NULL;
    static struct ip* ip=NULL;
    static int ipoff;
    static char buf[6*1024];
  /*  static struct fniff_tcp * tcp;
    static struct icmphdr* icmp;
    static struct udphdr* udp;*/
    	static int len=0;
	static char * myp;	 
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
	///if((eth_type!=0x0800))
	  //  return;
	
	if(vlan_flag)
	{
		ipoff=size_mac+4;
		ip=(struct ip*)(packet+ipoff);
	}	 	
 	else
 	{
 		ipoff=size_mac;
 		ip=(struct ip*)(packet+ipoff);
 	}
 
			
	sip=(ip->ip_src.s_addr);
	dip=(ip->ip_dst.s_addr);
	classid=hash_HB(sip,dip)&g_thread_mask;
	//msg("%d\n",classid);
	//usleep(1);
	//msg("classid=%d\n",classid);
	/*pthread_mutex_lock(&classifiers[classid].BC_mutex);	
	//msg("%d\n",pkthdr->caplen);
	if(pkthdr->caplen<2048)
	memcpy(buf,packet,pkthdr->caplen);

	pthread_mutex_unlock(&classifiers[classid].BC_mutex);	*/
	if (!g_getPacketStartFlag)
		return ;
	

	pthread_mutex_lock(&classifiers[classid].BC_mutex);
	
	BC* p=get_BC_node(&classifiers[classid].bc);

	
	pthread_mutex_unlock(&classifiers[classid].BC_mutex);	



	if(p==NULL)
		{

			sleep(1);
		msg("EISget bc node error\n");
			return;}
	memcpy(p->buf,packet,pkthdr->caplen<MAX_BUFFER_FOR_PACKET?pkthdr->caplen:MAX_BUFFER_FOR_PACKET-1);
		
	p->datalen = pkthdr->caplen < MAX_BUFFER_FOR_PACKET ? pkthdr->caplen : MAX_BUFFER_FOR_PACKET-1;	
	p->ip = p->buf+ipoff;
	
	pthread_mutex_lock(&classifiers[classid].work_mutex);
	if ( (classifiers[classid].tail == NULL) )
	{
		classifiers[classid].tail = classifiers[classid].head = p;		
	}
	else 
	{
		classifiers[classid].tail->next = p;
		classifiers[classid].tail = p;
	}	
	pthread_mutex_unlock(&classifiers[classid].work_mutex);	
	
   if (write(efd[classid], &count, 8) < 0)
    {
        perror("write event fd fail:\n");
        msg("%d,%d\n",efd[classid],classid);
       // return;
    }
 	packet_num++;
 	packet_len+=pkthdr->caplen; 
 	//sleep(1);
    //msg("write\n");
    //msg();
	/*char ipdotdecs[20]={0};
    char ipdotdecc[20]={0};
	inet_ntop(AF_INET,(void*)&(ip->ip_src),ipdotdecs,16);
	inet_ntop(AF_INET,(void*)&(ip->ip_dst),ipdotdecc,16);
	printf("%s-->%s: len:%d\n",ipdotdecs,ipdotdecc,pkthdr->caplen);*/

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
int set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;
	return 0;
}
int set_reuse(int fd)
{
	int  on = 1;
	int ret = setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );
	return ret;
}
void threadsocks(void* _id)
{
	int descr = (int)_id;
	while(!g_getPacketStartFlag)
	{
		sleep(1);
		if (exitflag)
			pthread_exit(NULL);
	}
	NS_TIME_START(time);
	pcap_loop(descr,-1,my_callback,NULL);
	
	msg ("ESI pcap_loop exit\n");
	
	NS_TIME_END(time);

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

	//char *filename = "/run/shm/a.pcap";
	//char *filename = "/home/zhao1/get.pcap";
	//char *filename = "/run/shm/get.pcap";
	char *filename = "./get.pcap";
	//descr = pcap_open_live(dev,MAX_BUFFER_FOR_PACKET,1 ,0,errbuf);
	descr =pcap_open_offline(filename, errbuf);

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
	signal(SIGHUP, sigproc);
	signal(SIGQUIT, sigproc);
	signal(SIGSTOP, sigproc);
	signal(SIGURG, sigproc);
	signal(SIGPIPE, sigproc);

	//////////////
	//compile ac dfa
	///////////////
	g_cpu_core = sysconf(_SC_NPROCESSORS_CONF);
	cpu_set_t cpumask;
	CPU_ZERO(&cpumask);
	CPU_SET((g_thread_at_core++%g_cpu_core), &cpumask);

	

	msg("cpu cores: %d\n",g_cpu_core);

	if (sched_setaffinity(0, sizeof(cpumask), &cpumask) == -1)
	{
		printf("warning: could not set CPU affinity, continuing...\n");
	}

	g_thread_mask = CLASSIFY_NUM-1;
	int ncalss;
	pthread_t ids[CLASSIFY_NUM];



	

	for(ncalss=0; ncalss<CLASSIFY_NUM; ++ncalss)
	{
		efd[ncalss] = eventfd(0, EFD_NONBLOCK);
		msg("efd=%d\n",efd[ncalss]);
        if (efd[ncalss] < 0)
        {
            msg("EIeventfd failed.");
            return;
        }

	}

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
		pthread_mutex_init(&classifiers[ncalss].BC_mutex,NULL);
		classifiers[ncalss].head=NULL;
		classifiers[ncalss].tail=NULL;
	
	}
	for(ncalss=0; ncalss<CLASSIFY_NUM; ++ncalss)
	{		
		//create thread
		int ret;
		ret=pthread_create(&ids[ncalss],NULL,(void *) threadpro,(void*)ncalss);
		if(ret!=0){ 
			printf ("Create pthread error!\n"); 
			exit (1); 
		} 
		//msg("EISpppppppppp");

	}

	
	pthread_mutex_init(&thread_mutex,NULL);
	
	
	



	
	msg("main start\n");
	sleep(2);
	#if 0
		NS_TIME_START(time);
		pcap_loop(descr,-1,my_callback,NULL);
		exitflag=1;
		NS_TIME_END(time);
	#endif
	//start pcap get
	pthread_t sockid;
	ret=pthread_create(&sockid,NULL,(void *) threadsocks,(void*)descr);
	if(ret!=0){ 
		printf ("Create pthread error!\n"); 
		exit (1); 
	} 

	
	int sockfd; 
	struct sockaddr_in my_addr; 
	struct sockaddr_in remote_addr; 
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) <0)
	{
		msg("socket error\n"); 
		exit(1);
	}
	set_reuse(sockfd);
	memset((char *)&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family=AF_INET;
	my_addr.sin_port=htons(SERVPORT);
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	/*if(inet_pton(AF_INET,"192.168.119.158",&my_addr.sin_addr)<=0) //±ŸµØµØÖ·×ª»»ÎªÍøÂçµØÖ· 
	{
		printf("invalid dest ip");
		exit(1);
	}*/
	
	if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) <0)
	{
		perror("bind");
		exit(1);
	}
	if(listen(sockfd, BACKLOG)<0)
	{
		perror("listen");
		exit(1);
	}
	int sin_size = sizeof(struct sockaddr_in);

	fd_set readfds;//
	struct timeval tv;
	#define SOCKBUF 256
	char sockbuf[SOCKBUF];
	int recvnum;
	int addrlen = sizeof(struct sockaddr_in);

	//int clientfd[20];
	int clientnum=0;
	int clientindex;
	while(1)
	{
		FD_ZERO(&readfds);
		FD_SET(sockfd,&readfds);
		for (clientindex = 0; clientindex < clientnum; ++clientindex) 
		{
			if (load_table[clientindex].clientfd != -1)
				FD_SET(load_table[clientindex].clientfd, &readfds);
		}
		
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		msg("wait for connect\n");
		ret=select(sockfd+1,&readfds,NULL,NULL,&tv);
		if(ret<0){printf("selecr error\n"); break;}
		else if (ret==0) 
		{
			if (exitflag)
			{
				break;
			}
			//printf("timeout\n");
			continue;
		}
		else
		{			
			if (FD_ISSET(sockfd, &readfds))
			{			

				if ((load_table[clientnum].clientfd = accept(sockfd, (struct sockaddr *)&remote_addr, &sin_size)) == -1)
				{
					perror("accept error");
					continue;
				}
				msg("accept=%d\n",load_table[clientnum].clientfd);
				set_nonblock(load_table[clientnum].clientfd);
				sleep(4);
				
				g_getPacketStartFlag=1;
				//send(load_table[clientnum].clientfd, &clientnum, sizeof(clientnum), 0);
				//clientnum++;

				//recvnum = recv(client_fd,sockbuf,SOCKBUF,0);	

			}
			else
			{
				for (clientindex = 0; clientindex < clientnum; ++clientindex) 
				{
					if (FD_ISSET(load_table[clientindex].clientfd, &readfds))
					{						
						recvnum = recv(load_table[clientindex].clientfd, sockbuf, 4, 0);	
						if (recvnum == 0 || recvnum < 4)
						{
							msg("recv :%d num\n", recvnum);
							close(load_table[clientindex].clientfd);
							load_table[clientindex].clientfd = -1;
						}			
					}
					
				}
				
			}
		}

		
	}
	//sleep(5);
	close(sockfd);
	msg("IS\ng_sendpacket=%ld\npacket_num=%ld\n",g_sendpacket,packet_num);
	msg ("ESI exitflag=1\n");
	exitflag = 1;
	speed1(NS_GET_TIMEP(time),packet_num,packet_len);
	msg("loop exit\n");
	/////////////////////////////////////
	//pthread_join(threadid,NULL);
	int i;
	for(i=0;i<PRO_MAX+2;++i)
	{

		printf("%s:%lld\n",pro_map[i],pronum[i]);
  	}
   	printf("losepacket=%lld\n",losepacket);
	//sem_post(&bin_sem);
	

	

	
	for(ncalss=0; ncalss<CLASSIFY_NUM; ++ncalss)
	{			
		pthread_join(ids[ncalss],NULL);

	}
	pthread_join(sockid,NULL);
	
	
	for(ncalss=0; ncalss<CLASSIFY_NUM; ++ncalss)
	{
		//del_HB(&hb);		
		del_HB(&classifiers[ncalss].hb, &classifiers[ncalss].sn);
		//acsmFree (acsm);		
		acsmFree (classifiers[ncalss].acsm);
		pthread_mutex_destroy(&classifiers[ncalss].work_mutex);
		close(efd[ncalss]);
		msg("%d ",maxnum[ncalss]);
	}
	msg("\nexit\n");
	return 0;
}


