#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#define hash_HB(ipsrc,  portsrc,ipdst, portdst ) \
((unsigned short)((ipsrc)^((ipsrc)>>16)^((portsrc))^(ipdst)^((ipdst)>>16)^((portdst))))
int main(void)
{
char addr_p[16]; /*IP地址的点分十进制字符串表示形式*/
struct in_addr addr_n;/*IP地址的二进制表示形式*/
if(inet_pton(AF_INET,"192.168.11.6",&addr_n)<0)/*地址由字符串转换为二级制数*/
{
perror("fail to convert");
exit(1);
}
printf("address:%x,%u\n",(addr_n.s_addr),hash_HB((addr_n.s_addr),21,ntohl(addr_n.s_addr),80));/*打印地址的16进制形式*/
if(inet_ntop(AF_INET,&addr_n,addr_p,(socklen_t )sizeof(addr_p))==NULL) /*地址由二进制数转换为点分十进制*/
{
perror("fail to convert");
exit(1);
}
unsigned int aa=addr_n.s_addr;
printf("%02x\n",aa);
printf("address:%s\n",addr_p);/*打印地址的点分十进制形式*/
return 0;
}
