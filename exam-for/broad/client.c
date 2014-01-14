
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include"deltans.h"
#define BUFLEN 4096
#define SEND_NUM 1
int
main (int argc, char **argv) 
{  
    struct sockaddr_in peeraddr,ia;  
    int sockfd; 
    char recmsg[BUFLEN + 1]; 
    unsigned int socklen, nret; 
    struct ip_mreq mreq; 

    /* 创建 socket 用于UDP通讯 */ 
    sockfd = socket (AF_INET, SOCK_DGRAM, 0); 
    if (sockfd < 0)
    {          
        printf ("socket creating err in udptalk\n");          
        exit (1);        
    } 
    /* 设置要加入组播的地址 */ 
    bzero(&mreq, sizeof (struct ip_mreq)); 
    
    inet_pton(AF_INET,"224.0.1.22",&ia.sin_addr);
    /* 设置组地址 */ 
    bcopy (&ia.sin_addr.s_addr, &mreq.imr_multiaddr.s_addr, sizeof (struct in_addr)); 
    /* 设置发送组播消息的源主机的地址信息 */ 
    mreq.imr_interface.s_addr = htonl (INADDR_ANY);  
    
    int ttl=255;
		setsockopt(sockfd,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl));//设置跳数
		
		
		int yes=0;
		setsockopt(sockfd,IPPROTO_IP,IP_MULTICAST_LOOP,&yes,sizeof(yes));//设置数据回送到本地回环接口


    /* 把本机加入组播地址，即本机网卡作为组播成员，只有加入组才能收到组播消息 */ 
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,sizeof (struct ip_mreq)) == -1)
    {     
        perror ("setsockopt");      
        exit (-1);   
    }
																		    /*******************************
																		    struct ip_mreq mreq; //加入广播组

																					mreq.imr_multiaddr.s_addr    = inet_addr(MCAST_ADDR); //广播地址
																					
																					mreq.imr_interface.s_addr    = htonl(INADDR_ANY); //网络接口为默认
																					
																					//将本机加入广播组
																					
																					err = setsockopt(s,    IPPROTO_IP, IP_ADD_MEMBERSHIP,&mreq, sizeof
																					    (mreq));
																					
																					if (err < 0)
																					
																					{
																					
																					perror("setsockopt():IP_ADD_MEMBERSHIP");
																					
																					return -4;
																					
																					}
   																	 *******************************/

    socklen = sizeof (struct sockaddr_in); 
    memset (&peeraddr, 0, socklen); 
    peeraddr.sin_family = AF_INET;
   // peeraddr.sin_port = htons (7838);
     peeraddr.sin_port = htons (6023);
  //   inet_pton(AF_INET, "224.0.1.22", &peeraddr.sin_addr); 
  
  peeraddr.sin_addr.s_addr=htonl(INADDR_ANY);//接收任意地址发送的数据
   // inet_pton(AF_INET, "224.0.1.2", &peeraddr.sin_addr); 

    /* 绑定自己的端口和IP信息到socket上 */ 
    if (bind(sockfd, (struct sockaddr *) &peeraddr,sizeof (struct sockaddr_in)) == -1)
    {      
        printf ("Bind error\n");      
        exit (0);    
    }
    
   
    	int n=0;
				int b=0;
				NS_TIME(time);
				int flag=0;
				int firstlen;
  
    /* 循环接收网络上来的组播消息 */ 
    for (;;)
    {     
        bzero (recmsg, BUFLEN + 1);     
        nret = recvfrom (sockfd, recmsg, BUFLEN, 0, (struct sockaddr *) &peeraddr, &socklen);
        if (nret<=0)
        {      
            printf ("recvfrom err in udptalk!\n");      
            exit (4);    
        }
         n++;
        	 if(!flag)
               	{
               		firstlen=nret;
               		flag=1;
               		NS_TIME_START(time);
               	}
               	if(recmsg[0]=='#')
									{
										b++;
										n--;
										//printf("end\n");
										if(b==SEND_NUM)
											break;
									
										}
               	   
       
      
    
    }
     NS_TIME_END(time);
          speed(NS_GET_TIMEP(time),n,firstlen);
         printf("recv:%d\n",n);
    //离开组播地址
    int ret=setsockopt(sockfd,IPPROTO_IP,IP_DROP_MEMBERSHIP,&mreq,sizeof(mreq));
		if(ret<0){
 		 perror("IP_DROP_MEMBERSHIP");
  		return -1;
		}
close(sockfd);

}