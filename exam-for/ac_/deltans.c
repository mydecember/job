#include"stdio.h"
#include"time.h"
#include"deltans.h"
#include"sys/time.h"
//#include"sysdep.h"
//#define __TEST__




long delta_time (struct timespec * now,
                 struct timespec * before) {
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
 // return((delta_seconds * 1000000000) + delta_microseconds);
printf("\n[%lds, %ldns]\n",delta_seconds,delta_microseconds);
}
#define DELAY_INI() struct timespec _delay_time1 , _delay_time2;long m_sec,m_delay=0,m_temp
#define DELAY(n) ({clock_gettime(CLOCK_REALTIME,&_delay_time1);\
	do{\
	clock_gettime(CLOCK_REALTIME,&_delay_time2);\
	m_delay=m_temp=_delay_time2.tv_nsec-_delay_time1.tv_nsec;\
	if(m_temp<0){\
	m_delay=1000000000+m_temp;\
	}\
	}while(m_delay<n);\
	})
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
