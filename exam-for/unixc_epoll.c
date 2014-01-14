#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include"errno.h"
#include"fcntl.h"
#include"deltans.h"
#define PATH "/tmp/unixs"
#define MYPATH "/tmp/unixc"
ssize_t socket_send(int sockfd, const char* buffer, size_t buflen,int flag,struct sockaddr* adds,int slen)
{
  ssize_t tmp;
  size_t total = buflen;
  const char *p = buffer;

  while(1)
  {
  	//sendto(sockfd,send_buf,strlen(send_buf),0,(struct sockaddr*)&addr,len);
    tmp = sendto(sockfd, p, total, flag,adds,slen);
    if(tmp < 0)
    {
      // 当send收到信号时,可以继续写,但这里返回-1.
      if(errno == EINTR)
      {
      	perror("inter error\n");
        return -1;
      }
      if(errno == ECONNREFUSED)
      {
      	perror("connection refuse error\n");
      	return -2;
      }

      // 当socket是非阻塞时,如返回此错误,表示写缓冲队列已满,
      // 在这里做延时后再重试.
      if(errno == EAGAIN)
      {
      	perror("again\n");
       // usleep(1000);
        continue;
      }
			perror("send <0\n");
      return -3;
    }

    if((size_t)tmp == total)
     {
     	
     	 return buflen;
    }

    total -= tmp;
    p += tmp;
  }

  return tmp;
}
  int setnonblocking(int sockfd)  
{  
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1)  
 {  
        return -1;  
    }  
    return 0;  
}  
int unix_init(struct sockaddr_un *addr,struct sockaddr_un *addrc)
{
    int sockfd = 0;
    
    unlink(MYPATH);
    bzero(addr,sizeof(struct sockaddr_un));
    ///
     bzero(addrc,sizeof(struct sockaddr_un));
    //
  
    addr->sun_family = AF_UNIX;
    strcpy(addr->sun_path,PATH);
    
    
    /////
    addrc->sun_family = AF_UNIX;
    strcpy(addrc->sun_path,"/tmp/unixc");
    //////
  
    sockfd = socket(AF_UNIX,SOCK_DGRAM,0);
    if(sockfd < 0)
    {
        perror("socket error");
      //  exit(-1);
      return -1;
    }
  //  setnonblocking(sockfd);
  /////////////////////////////////
  unsigned int len = strlen(addrc->sun_path) + sizeof(addrc->sun_family);
   if(bind(sockfd,(struct sockaddr *)addrc,len) < 0)
    {
        perror("bind error");
        close(sockfd);
       // exit(-1);
       return -1;
    }
    printf("Bind is ok\n");
   
  ///////////////////////////////
 
    return sockfd;
}
#ifdef __TEST__UNIXC__
int main()
{
	struct sockaddr_un addr,addrc;
	
	int sockfd=unix_init(&addr,&addrc);
	if(sockfd<=0)
		{
			perror("sock creat error\n");
			exit(1);
			}
			printf("sockfd=%d\n",sockfd);
			
	 static long long  counter = 0;
	 int len;
        char send_buf[1000000] = "";
      
        //sprintf(send_buf,"Counter 2 is %d",counter);
        memset(send_buf,'a',1700);
       len = strlen(addr.sun_path)+sizeof(addr.sun_family);
        NS_TIME(time);
        int sendnum=654321;
        NS_TIME_START(time);
        int sendlen=strlen(send_buf);
        int nn;
    while(sendnum>0)
    {
        sendnum--;
        
       // nn=sendto(sockfd,send_buf,strlen(send_buf),0,(struct sockaddr*)&addr,len);
       nn=socket_send(sockfd,send_buf,sendlen,0,(struct sockaddr*)&addr,len);
       if(nn>=len)
        	  counter++;
        	  else
        	  	printf("error\n");
        	//  if(nn<=0)
        	//  	printf("%d:%s\n",errno,strerror(errno));
    
    // usleep(500);
      // sleep(1);
    }
    socket_send(sockfd,"############",strlen("############"),0,(struct sockaddr*)&addr,len);
    NS_TIME_END(time);
     printf("Send: %d,%lld\n",nn,counter);
	
	return 0;
}
#endif