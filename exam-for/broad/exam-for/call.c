#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* 如果没有pcap的系统，要自己下载一个 */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include"deltans.h"
#include <signal.h>
#define SEND_NUM 1
#define ALARM_SLEEP 1
/* just print a count every time we have a packet...                        */
int exitflag=0;
int flag=0;
int firstlen;
NS_TIME(time);
int n=0;
int b=0;
float f[60][10]={0.0};
int alarmnum=0;

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

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    static int count = 0;
   // fprintf(stdout,"%d,%d,%d,%s\n ",pkthdr->caplen,pkthdr->len,count,&packet[42]);
   // fflush(stdout);
 	if(!flag&&(packet[46]=='*'))
               	{
			signal(SIGALRM, my_sigalarm);
			alarm(ALARM_SLEEP);
               		firstlen=pkthdr->caplen;
               		flag=1;
               		NS_TIME_START(time);
               	}
if(packet[46]=='$')
	count++;
	if(packet[46]=='#'&&packet[47]=='#')
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
								
									
	}
   
}
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
  
  printf("MASK: %s\n",mask);
 descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

get_sys_info(f[0],10);
usleep(600000);

 pcap_loop(descr,-1,my_callback,NULL);
  return 0;
}
