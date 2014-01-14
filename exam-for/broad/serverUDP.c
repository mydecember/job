#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include"deltans.h"
#include"signal.h"
#define PORT 6023
 int exitflag=0;
 	NS_TIME(time);
 void sigroutine(int dunno) { /* 信号处理例程，其中dunno将会得到信号的值 */ 
/*switch (dunno) { 
case 1: 
printf("Get a signal -- SIGHUP "); 

break; 
case 2: 
printf("Get a signal -- SIGINT "); 

break; 
case 3: 
printf("Get a signal -- SIGQUIT "); 

break; 
} */
  NS_TIME_END(time);
 
exitflag=1;
return; 
} 
int main()  
{  
    setvbuf(stdout, NULL, _IONBF, 0);   
    fflush(stdout);   
   signal(SIGHUP, sigroutine); //* 下面设置三个信号的处理方法 
signal(SIGINT, sigroutine); 
signal(SIGQUIT, sigroutine); 
    int sock = -1;  
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)   
    {     
        printf("socket error\n");   
        return -1;  
    }     
      
    const int opt = 1;  
    //设置该套接字为广播类型，  
    int nb = 0;  
    nb = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&opt, sizeof(opt));  
    if(nb == -1)  
    {  
        printf("set socket error...\n");  
        return -1;  
    }  
  
    struct sockaddr_in addrto;  
    bzero(&addrto, sizeof(struct sockaddr_in));  
    addrto.sin_family=AF_INET;  
    addrto.sin_addr.s_addr=htonl(INADDR_BROADCAST);  
    addrto.sin_port=htons(PORT);  
    int nlen=sizeof(addrto);  
  int n=20000;
  char smsg[] = {"abcdefaagkghkaakhgkaakhjlhjlhaaaaaaaaaaaaaaangvnvnv"};
  
   char sendBuf[4096];
   char sendMy[4096]={0};
        
         memset(sendBuf,0,sizeof(sendBuf));
	memset(sendBuf,'$',1000);
	memset(&sendBuf[strlen(sendBuf)],'b',1);
	memset(&sendBuf[strlen(sendBuf)],'n',10);
	
	memset(sendMy,'*',strlen(sendBuf));

	int sendlen=strlen(sendBuf);
  /*  while(n>0)  
    {  
    	
         n--;
         usleep(1);
        //从广播地址发送消息  
          
        int ret=sendto(sock, smsg, strlen(smsg), 0, (struct sockaddr*)&addrto, nlen);  
        if(ret<=0)  
        {  
            printf("send error....\n");  
        }  
        else  
        {         
           // printf("ok \n");    
        }  
    }  */  
    	DELAY_INI();
    	size_t len;
    	 len=sendto(sock, sendMy,sendlen , 0, (struct sockaddr*)&addrto,nlen );
    	 n=0;
    NS_TIME_START(time);
    while(!exitflag)
         {
					
               // usleep(1);
//DELAY(656);
//DELAY(3000);//832.9
DELAY(2000);//936.6
//DELAY(1900);//965.3
//DELAY(9000);//523.9
//DELAY(100000);//84.1
//DELAY(1000);
                   

                  // fgets(sendBuf, 2048, stdin);

                  // len=sendto(sockfd, sendBuf, strlen(sendBuf), 0, (struct sockaddr*)&srvAddr, sizeof(srvAddr));
                    len=sendto(sock, sendBuf,sendlen , 0, (struct sockaddr*)&addrto,nlen );
                    n++;
                   if(len<sendlen)
                   	{
                   		perror("eror:");
                   		printf("len:%d\n",len);
                   	}
              			

                 //  len = recvfrom(sockfd, sendBuf, 2048, 0, NULL, NULL);

              //   sendBuf[len] = '\0';

                //   printf("%s", sendBuf);

         }
       
       
			memset(sendBuf,'#',1024);
				sendto(sock,sendBuf, strlen(sendBuf), 0, (struct sockaddr*)&addrto, nlen);
			//	 for(i=0;i<SEND_NUM;++i)
	 	//	len=sendto(sockfd, sendBuf,sendlen , 0, (struct sockaddr*)&clientAddr[i],addlen );
				 speed(NS_GET_TIMEP(time),n,sendlen);
				//sendto(sockfd,sendBuf, strlen(sendBuf), 0, (struct sockaddr*)&srvAddr, sizeof(srvAddr));
				//sendto(sockfd,sendBuf, strlen(sendBuf), 0, (struct sockaddr*)&srvAddr, sizeof(srvAddr));
				sleep(4);
      //   sleep(10);
         close(sock);
        // time
		printf("send:%d\n",n);
         return 0;
  
    return 0;  
}  
