#include"stdio.h"
#include"time.h"
#include"deltans.h"
#include"sys/time.h"
//#include"sysdep.h"
//#define __TEST__




struct timespec delta_time (struct timespec * now,
                 struct timespec * before) {
                 	struct timespec tem;
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_nsec - before -> tv_nsec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000000;  /* 1e6 */
    -- delta_seconds;
  }
  tem.tv_sec=delta_seconds;
  tem.tv_nsec=delta_microseconds;
   // return((delta_seconds * 1000000000) + delta_microseconds);
printf("\n[%lds, %ldns]\n",delta_seconds,delta_microseconds);
  return tem;

}

#ifdef __TEST__
int main()
{
	NS_TIME(time);
	int n=1;//1000000*10;
	struct timeval tv;
	tv.tv_sec=0;
	tv.tv_usec=500;
	//select(0,NULL,NULL,NULL,&tv);

	DELAY_INI();
//while(1){
	NS_TIME_START(time);
	//select(0,NULL,NULL,NULL,&tv);
//	DELAY(500);
	//usleep(1);
	while(n>0)
	{
	//usleep(1);
//	udelay(1);
	DELAY(656);
	n--;
	}
	
	//sleep(2);
	//usleep(500);
	NS_TIME_END(time);

	//long t = delta_time(&timeend,&timen);
	//printf("time:%ld\n",t);
}
#endif

void speed(struct timespec *p, int n,int len)
{
//printf("%ld,%ld\n",p->tv_sec,p->tv_nsec);
	double tns=p->tv_sec*1000000+p->tv_nsec/1000;
	//printf("(42.0+len)*n=%f\n",(42.0+len)*n);
	printf("packet per sec:%0.1f\nspeed:%0.1fMbps\n",n*1.0/p->tv_sec,(((42.0+24+len)*n)/(tns))*8);// 24= 8 preamble + 4 crc +12 IFG  udp»ﬂ”‡÷¡…Ÿ66/*
}