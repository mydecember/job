#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#define hash_HB(ipsrc,  portsrc,ipdst, portdst ) \
((unsigned short)((ipsrc)^((ipsrc)>>16)^((portsrc))^(ipdst)^((ipdst)>>16)^((portdst))))
int main(void)
{
char addr_p[16]; /*IP��ַ�ĵ��ʮ�����ַ�����ʾ��ʽ*/
struct in_addr addr_n;/*IP��ַ�Ķ����Ʊ�ʾ��ʽ*/
if(inet_pton(AF_INET,"192.168.11.6",&addr_n)<0)/*��ַ���ַ���ת��Ϊ��������*/
{
perror("fail to convert");
exit(1);
}
printf("address:%x,%u\n",(addr_n.s_addr),hash_HB((addr_n.s_addr),21,ntohl(addr_n.s_addr),80));/*��ӡ��ַ��16������ʽ*/
if(inet_ntop(AF_INET,&addr_n,addr_p,(socklen_t )sizeof(addr_p))==NULL) /*��ַ�ɶ�������ת��Ϊ���ʮ����*/
{
perror("fail to convert");
exit(1);
}
unsigned int aa=addr_n.s_addr;
printf("%02x\n",aa);
printf("address:%s\n",addr_p);/*��ӡ��ַ�ĵ��ʮ������ʽ*/
return 0;
}
